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

package clouddns

import (
	"fmt"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	val "github.com/jetstack/cert-manager/pkg/apis/certmanager/validation/util"
	"reflect"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
)


func init() {
	dns.DefaultRegistry.Register("clouddns", NewFactory(nil))
}

type Constructor func (project string, saBytes []byte, dns01Nameservers []string, ambient bool) (*DNSProvider, error)

type Factory struct {
	constructor Constructor
}

func NewFactory(constructor Constructor) dns.ProviderFactory {
	if constructor==nil {
		constructor=NewDNSProvider
	}
	return &Factory{constructor}
}

func (f *Factory) ResolverType() reflect.Type {
	return reflect.TypeOf(&DNSProvider{})
}

func (f *Factory) Validate(rawconfig interface{}, fldPath *field.Path)  field.ErrorList{
	var config v1alpha1.ACMEIssuerDNS01ProviderCloudDNS
	el := util.Validate(rawconfig, &config, fldPath)
	if len(el) == 0 {
		// if either of serviceAccount.name or serviceAccount.key is set, we
		// validate the entire secret key selector
		if config.ServiceAccount.Name != "" || config.ServiceAccount.Key != "" {
			el = append(el, val.ValidateSecretKeySelector(&config.ServiceAccount, fldPath.Child( "serviceAccountSecretRef"))...)
		}
		if len(config.Project) == 0 {
			el = append(el, field.Required(fldPath.Child( "project"), ""))
		}
	}
	return el
}

func (f *Factory) Create(s *dns.Solver, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, resourceNamespace string, rawconfig interface{}) (dns.Interface, error) {
	var config v1alpha1.ACMEIssuerDNS01ProviderCloudDNS

	err:=util.GetConfig(rawconfig,&config)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshalling clouddns config")
	}

	var keyData []byte

	// if the serviceAccount.name field is set, we will load credentials from
	// that secret.
	// If it is not set, we will attempt to instantiate the provider using
	// ambient credentials (if enabled).
	if config.ServiceAccount.Name != "" {
		saSecret, err := s.Secret(resourceNamespace,config.ServiceAccount.Name)
		if err != nil {
			return nil, fmt.Errorf("error getting clouddns service account: %s", err)
		}

		saKey := config.ServiceAccount.Key
		keyData = saSecret.Data[saKey]
		if len(keyData) == 0 {
			return nil, fmt.Errorf("specfied key %q not found in secret %s/%s", saKey, saSecret.Namespace, saSecret.Name)
		}
	}

	// attempt to construct the cloud dns provider
	impl, err := f.constructor(config.Project, keyData, s.DNS01Nameservers, s.CanUseAmbientCredentials(issuer))
	if err != nil {
		return nil, fmt.Errorf("error instantiating google clouddns challenge solver: %s", err)
	}

	return impl, nil
}

