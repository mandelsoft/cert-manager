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
	"github.com/jetstack/cert-manager/pkg/controller"
	"k8s.io/client-go/listers/core/v1"
)

func SolverForChallenge(s *Solver, issuer v1alpha1.GenericIssuer, ch *v1alpha1.Challenge) (solver, *v1alpha1.ACMEIssuerDNS01Provider, error) {
  return s.solverForChallenge(issuer,ch)
}

func NewSolver2(ctx *controller.Context, lister v1.SecretLister, providers *Registry) *Solver {
	return &Solver{
		ctx,
		lister,
		providers,
	}
}
