/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package util

import (
	"fmt"
	"github.com/json-iterator/go"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"reflect"
)

var JSONIterator = JsonIterator()


// CaseSensitiveJsonIterator returns a jsoniterator API that's configured to be
// case-sensitive when unmarshalling, and otherwise compatible with
// the encoding/json standard library.
func JsonIterator() jsoniter.API {
	config := jsoniter.Config{
		EscapeHTML:             true,
		SortMapKeys:            true,
		ValidateJsonRawMessage: true,
	}.Froze()
	return config
}

func Validate(data interface{}, config interface{}, fldPath *field.Path) field.ErrorList {
	el:=field.ErrorList{}
	if data==nil {
		return append( el, field.Required(fldPath, ""))
	}
	err:= GetConfig(data,config)
	if err != nil {
		el = append( el, field.Invalid(fldPath, "<config>", fmt.Sprintf("error unmarshalling config: %s", err)))
	}
	return el
}

func GetConfig(data interface{}, config interface{}) error {
	if config == nil {
		return fmt.Errorf("no config target specified")
	}
	if data == nil {
		return fmt.Errorf("no config data specified")
	}
	if reflect.TypeOf(data) == reflect.TypeOf(config) && reflect.TypeOf(config).Kind()==reflect.Ptr {
		reflect.ValueOf(config).Elem().Set(reflect.ValueOf(data).Elem())
	} else {
		if raw,ok := data.(*runtime.RawExtension); ok {
			return UnmarshalInto(raw.Raw, config)
		}
		return fmt.Errorf("unknown data type %T", data)
	}
	return nil
}

func UnmarshalInto(data []byte, into interface{}) error {
		return JSONIterator.Unmarshal(data, into)
}