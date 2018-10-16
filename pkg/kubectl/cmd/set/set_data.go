/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package set

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/kubectl"
	"k8s.io/kubernetes/pkg/kubectl/cmd/templates"
	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/kubectl/resource"
	"k8s.io/kubernetes/pkg/kubectl/util/i18n"
)

var (
	data_long = templates.LongDesc(i18n.T(`
		Update a Secret or configmap based on a file, directory, or specified literal value.`))

	data_example = templates.Examples(i18n.T(`
		# Update secret  of configmap data, key=name and value=myname
		kubectl set data secret my-secret --from-literal=name=myname`))
)

// DataOptions encapsulates the data required to perform the operation.
type DataOptions struct {
	fileNameOptions resource.FilenameOptions
	Mapper          meta.RESTMapper
	Out             io.Writer
	Err             io.Writer
	DryRun          bool
	Cmd             *cobra.Command
	ShortOutput     bool
	all             bool
	record          bool
	Output          string
	changeCause     string
	Local           bool
	Infos           []*resource.Info

	FileSources    []string
	LiteralSources []string
	EnvFileSource  string
}

func NewCmdData(f cmdutil.Factory, out, err io.Writer) *cobra.Command {
	options := &DataOptions{
		Out: out,
		Err: err,
	}

	cmd := &cobra.Command{
		Use: "data (-f FILENAME | TYPE NAME) [--from-file=[key=]source] [--from-literal=key1=value1] [--from-env-file=[key=]source] [--dry-run]",
		DisableFlagsInUseLine: true,
		Short:   i18n.T("Update data for secret or configmap"),
		Long:    data_long,
		Example: data_example,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(options.Complete(f, cmd, args))
			cmdutil.CheckErr(options.Validate())
			cmdutil.CheckErr(options.Run())
		},
	}

	cmdutil.AddPrinterFlags(cmd)
	cmd.Flags().StringSlice("from-file", []string{}, "Key file can be specified using its file path, in which case file basename will be used as configmap key, or optionally with a key and file path, in which case the given key will be used.  Specifying a directory will iterate each named file in the directory whose basename is a valid configmap key.")
	cmd.Flags().StringArray("from-literal", []string{}, "Specify a key and literal value to insert in configmap (i.e. mykey=somevalue)")
	cmd.Flags().String("from-env-file", "", "Specify the path to a file to read lines of key=val pairs to create a configmap (i.e. a Docker .env file).")
	cmd.Flags().BoolVar(&options.Local, "local", false, "If true, set image will NOT contact api-server but run locally.")
	cmdutil.AddRecordFlag(cmd)
	cmdutil.AddDryRunFlag(cmd)
	cmdutil.AddIncludeUninitializedFlag(cmd)
	return cmd
}

// Complete configures DataOptions from command line args.
func (o *DataOptions) Complete(f cmdutil.Factory, cmd *cobra.Command, args []string) error {
	o.Mapper, _ = f.Object()
	o.ShortOutput = cmdutil.GetFlagString(cmd, "output") == "name"
	o.record = cmdutil.GetRecordFlag(cmd)
	o.changeCause = f.Command(cmd, false)
	o.DryRun = cmdutil.GetDryRunFlag(cmd)
	o.Output = cmdutil.GetFlagString(cmd, "output")
	o.FileSources = cmdutil.GetFlagStringSlice(cmd, "from-file")
	o.LiteralSources = cmdutil.GetFlagStringArray(cmd, "from-literal")
	o.EnvFileSource = cmdutil.GetFlagString(cmd, "from-env-file")
	o.Cmd = cmd

	cmdNamespace, enforceNamespace, err := f.DefaultNamespace()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New("Secret or ConfigMap is required")
	}
	resources := args
	includeUninitialized := cmdutil.ShouldIncludeUninitialized(cmd, false)
	builder := f.NewBuilder().
		Internal().
		LocalParam(o.Local).
		ContinueOnError().
		NamespaceParam(cmdNamespace).DefaultNamespace().
		FilenameParam(enforceNamespace, &o.fileNameOptions).
		IncludeUninitialized(includeUninitialized).
		Flatten()
	if !o.Local {
		builder.ResourceTypeOrNameArgs(o.all, resources...).
			Latest()
	}
	o.Infos, err = builder.Do().Infos()
	if err != nil {
		return err
	}
	return nil
}

func (o *DataOptions) Validate() error {
	errors := []error{}
	if len(o.EnvFileSource) > 0 && (len(o.FileSources) > 0 || len(o.LiteralSources) > 0) {
		errors = append(errors, fmt.Errorf("from-env-file cannot be combined with from-file or from-literal"))
	}
	return utilerrors.NewAggregate(errors)
}

// Run creates and applies the patch either Locally or calling apiserver.
func (o *DataOptions) Run() error {
	patches := CalculatePatches(o.Infos, cmdutil.InternalVersionJSONEncoder(), func(info *resource.Info) ([]byte, error) {
		transformed, err := o.updateDataForObject(info.Object, addData)
		if transformed && err == nil {
			return runtime.Encode(cmdutil.InternalVersionJSONEncoder(), info.AsVersioned())
		}
		return nil, err
	})

	allErrs := []error{}
	for _, patch := range patches {
		info := patch.Info
		if patch.Err != nil {
			allErrs = append(allErrs, fmt.Errorf("error: %s/%s %v\n", info.Mapping.Resource, info.Name, patch.Err))
			continue
		}

		//no changes
		if string(patch.Patch) == "{}" || len(patch.Patch) == 0 {
			allErrs = append(allErrs, fmt.Errorf("info: %s %q was not changed\n", info.Mapping.Resource, info.Name))
			continue
		}

		if o.Local || o.DryRun {
			if err := cmdutil.PrintObject(o.Cmd, patch.Info.AsVersioned(), o.Out); err != nil {
				return err
			}
			continue
		}

		obj, err := resource.NewHelper(info.Client, info.Mapping).Patch(info.Namespace, info.Name, types.StrategicMergePatchType, patch.Patch)
		if err != nil {
			allErrs = append(allErrs, fmt.Errorf("failed to patch data to : %v\n", err))
			continue
		}
		info.Refresh(obj, true)

		if len(o.Output) > 0 {
			if err := cmdutil.PrintObject(o.Cmd, info.AsVersioned(), o.Out); err != nil {
				return err
			}
			continue
		}
		cmdutil.PrintSuccess(o.ShortOutput, o.Out, info.Object, o.DryRun, "data updated")
	}
	return utilerrors.NewAggregate(allErrs)
}

func getData(objType string, obj interface{}, fileSources, literalSources []string, envFileSource string) error {
	if objType == "secret" {
		if len(fileSources) > 0 {
			if err := kubectl.HandleFromFileSources(obj.(*v1.Secret), fileSources); err != nil {
				return err
			}
		}
		if len(literalSources) > 0 {
			if err := kubectl.HandleFromLiteralSources(obj.(*v1.Secret), literalSources); err != nil {
				return err
			}
		}
		if len(envFileSource) > 0 {
			if err := kubectl.HandleFromEnvFileSource(obj.(*v1.Secret), envFileSource); err != nil {
				return err
			}
		}
	} else if objType == "configmap" {
		if len(fileSources) > 0 {
			if err := kubectl.HandleConfigMapFromFileSources(obj.(*v1.ConfigMap), fileSources); err != nil {
				return err
			}
		}
		if len(literalSources) > 0 {
			if err := kubectl.HandleConfigMapFromLiteralSources(obj.(*v1.ConfigMap), literalSources); err != nil {
				return err
			}
		}
		if len(envFileSource) > 0 {
			if err := kubectl.HandleConfigMapFromEnvFileSource(obj.(*v1.ConfigMap), envFileSource); err != nil {
				return err
			}
		}
	}
	return nil
}

func (o *DataOptions) updateDataForObject(obj runtime.Object, fn func(string, runtime.Object, interface{}) (bool, map[string]string, map[string][]byte)) (bool, error) {
	switch t := obj.(type) {
	case *core.Secret:
		secretObj := &v1.Secret{}
		secretObj.Data = map[string][]byte{}
		err := getData("secret", secretObj, o.FileSources, o.LiteralSources, o.EnvFileSource)
		if err != nil {
			return false, err
		}
		transformed, _, bindata := fn("secret", t, secretObj.Data)
		t.Data = bindata
		return transformed, nil
	case *core.ConfigMap:
		configMapObj := &v1.ConfigMap{}
		configMapObj.Data = map[string]string{}
		configMapObj.BinaryData = map[string][]byte{}
		err := getData("configmap", configMapObj, o.FileSources, o.LiteralSources, o.EnvFileSource)
		if err != nil {
			return false, err
		}
		transformed, data, bindata := fn("configmap", t, configMapObj.Data)
		t.Data = data
		t.BinaryData = bindata
		return transformed, nil
	default:
		return false, fmt.Errorf("setting data is only supported for Secrets and ConfigMaps")
	}
}

func addData(objType string, obj runtime.Object, target interface{}) (bool, map[string]string, map[string][]byte) {
	transformed := false
	var updatedData map[string]string = nil
	var updatedBinData map[string][]byte = nil
	if objType == "secret" {
		updatedBinData = obj.(*core.Secret).Data
	} else if objType == "configmap" {
		updatedData = obj.(*core.ConfigMap).Data
		updatedBinData = obj.(*core.ConfigMap).BinaryData
	}

	if updatedBinData != nil {
		for keyName, value := range target.(map[string][]byte) {
			if _, exists := updatedBinData[keyName]; !exists {
				updatedBinData[keyName] = value
				transformed = true
			}
		}
	}

	if updatedData != nil {
		for keyName, value := range target.(map[string]string) {
			if _, exists := updatedData[keyName]; !exists {
				updatedData[keyName] = value
				transformed = true
			}
		}
	}
	return transformed, updatedData, updatedBinData
}
