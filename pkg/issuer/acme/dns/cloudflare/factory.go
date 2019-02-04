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

package cloudflare

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	val "github.com/jetstack/cert-manager/pkg/apis/certmanager/validation/util"
	"reflect"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
)


func init() {
	dns.DefaultRegistry.Register("cloudflare", NewFactory(nil))
}

type Constructor func (email, key string, dns01Nameservers []string) (*DNSProvider, error)

type Factory struct {
	constructor Constructor
}

func NewFactory(constructor Constructor) dns.ProviderFactory {
	if constructor==nil {
		constructor=NewDNSProviderCredentials
	}
	return &Factory{constructor}
}

func (f *Factory) ResolverType() reflect.Type {
	return reflect.TypeOf(&DNSProvider{})
}

func (f *Factory) Validate(rawconfig interface{}, fldPath *field.Path)  field.ErrorList{
	var config v1alpha1.ACMEIssuerDNS01ProviderCloudflare
	el := util.Validate(rawconfig, &config, fldPath)
	if len(el) == 0 {
		el = append(el, val.ValidateSecretKeySelector(&config.APIKey, fldPath.Child( "apiKeySecretRef"))...)
		if len(config.Email) == 0 {
			el = append(el, field.Required(fldPath.Child( "email"), ""))
		}
	}
	return el
}

func (f *Factory) Create(s *dns.Solver, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, resourceNamespace string, rawconfig interface{}) (dns.Interface, error) {
	var config v1alpha1.ACMEIssuerDNS01ProviderCloudflare

	glog.Infof("************ cloudflare create\n")
	err:=util.GetConfig(rawconfig, &config)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshalling cloudflare config")
	}

	apiKeySecret, err := s.Secret(resourceNamespace,config.APIKey.Name)
	if err != nil {
		return nil, fmt.Errorf("error getting cloudflare service account: %s", err)
	}

	email := config.Email
	apiKey := string(apiKeySecret.Data[config.APIKey.Key])

	impl, err := f.constructor(email, apiKey, s.DNS01Nameservers)
	if err != nil {
		return nil, fmt.Errorf("error instantiating cloudflare challenge solver: %s", err)
	}

	return impl, nil
}

