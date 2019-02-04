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

package azuredns

import (
	"fmt"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
    val "github.com/jetstack/cert-manager/pkg/apis/certmanager/validation/util"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"reflect"
)


func init() {
	dns.DefaultRegistry.Register("azuredns", NewFactory(nil))
}

type Constructor func (clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, zoneName string, dns01Nameservers []string) (*DNSProvider, error)

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
	var config v1alpha1.ACMEIssuerDNS01ProviderAzureDNS
	el := util.Validate(rawconfig, &config, fldPath)
	if len(el) == 0 {
		el = append(el, val.ValidateSecretKeySelector(&config.ClientSecret, fldPath.Child("clientSecretSecretRef"))...)
		if len(config.ClientID) == 0 {
			el = append(el, field.Required(fldPath.Child("clientID"), ""))
		}
		if len(config.SubscriptionID) == 0 {
			el = append(el, field.Required(fldPath.Child("subscriptionID"), ""))
		}
		if len(config.TenantID) == 0 {
			el = append(el, field.Required(fldPath.Child( "tenantID"), ""))
		}
		if len(config.ResourceGroupName) == 0 {
			el = append(el, field.Required(fldPath.Child("resourceGroupName"), ""))
		}
	}
	return el
}

func (f *Factory) Create(s *dns.Solver, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge, resourceNamespace string, rawconfig interface{}) (dns.Interface, error) {
	var config v1alpha1.ACMEIssuerDNS01ProviderAzureDNS

	err:= util.GetConfig(rawconfig, &config)
	if err != nil {
		return nil, errors.Wrap(err, "error unmarshalling azuredns config")
	}

	clientSecret, err := s.Secret(resourceNamespace,config.ClientSecret.Name)
	if err != nil {
		return  nil, fmt.Errorf("error getting azuredns client secret: %s", err)
	}

	clientSecretBytes, ok := clientSecret.Data[config.ClientSecret.Key]
	if !ok {
		return  nil, fmt.Errorf("error getting azure dns client secret: key '%s' not found in secret", config.ClientSecret.Key)
	}

	impl, err := f.constructor(
		config.ClientID,
		string(clientSecretBytes),
		config.SubscriptionID,
		config.TenantID,
		config.ResourceGroupName,
		config.HostedZoneName,
		s.DNS01Nameservers,
	)
	if err != nil {
		return nil, fmt.Errorf("error instantiating azuredns challenge solver: %s", err)
	}
	return impl, nil
}
