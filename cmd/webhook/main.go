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

package main

import (
	"flag"

	"github.com/openshift/generic-admission-server/pkg/cmd"

	"github.com/jetstack/cert-manager/pkg/apis/certmanager/validation/webhooks"
)

var certHook cmd.ValidatingAdmissionHook = &webhooks.CertificateAdmissionHook{}
var issuerHook cmd.ValidatingAdmissionHook = &webhooks.IssuerAdmissionHook{}
var clusterIssuerHook cmd.ValidatingAdmissionHook = &webhooks.ClusterIssuerAdmissionHook{}

func main() {
	// Avoid "logging before flag.Parse" errors from glog
	flag.CommandLine.Parse([]string{})

	cmd.RunAdmissionServer(
		certHook,
		issu/*
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
erHook,
		clusterIssuerHook,
	)
}
