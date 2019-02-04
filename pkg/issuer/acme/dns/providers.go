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

package dns

import (
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"reflect"
	"sync"
)

type Interface interface {
	solver
}

type ProviderFactory interface {
	Validate(config interface{}, fldPath *field.Path) field.ErrorList
	Create(s *Solver, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, resourceNamespace string, config interface{}) (Interface, error)
	ResolverType() reflect.Type
}

var DefaultRegistry = NewRegistry()

type Registry struct {
	lock sync.RWMutex
	factories map[string]ProviderFactory
}

func NewRegistry() *Registry {
	return &Registry{factories: map[string]ProviderFactory{} }
}

func (r *Registry) Register(name string, factory ProviderFactory) *Registry {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.factories[name]=factory
	return r
}

func (r *Registry) Get(name string) ProviderFactory {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return r.factories[name]
}
