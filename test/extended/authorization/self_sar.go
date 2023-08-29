package authorization

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	g "github.com/onsi/ginkgo/v2"
	authorizationv1 "github.com/openshift/api/authorization/v1"
	oauthv1 "github.com/openshift/api/oauth/v1"
	v1 "github.com/openshift/api/user/v1"
	authorizationv1typedclient "github.com/openshift/client-go/authorization/clientset/versioned/typed/authorization/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	exutil "github.com/openshift/origin/test/extended/util"
)

var _ = g.Describe("[sig-auth][Feature:OpenShiftAuthorization] self-SAR compatibility", func() {
	defer g.GinkgoRecover()
	oc := exutil.NewCLI("bootstrap-policy")

	g.Context("", func() {
		g.Describe("TestBootstrapPolicySelfSubjectAccessReviews", func() {
			g.It(fmt.Sprintf("should succeed [apigroup:user.openshift.io][apigroup:authorization.openshift.io]"), func() {
				t := g.GinkgoT()

				valerieName := oc.CreateUser("valerie-").Name
				valerieClientConfig := oc.GetClientConfigForUser(valerieName)

				askCanICreatePolicyBindings := &authorizationv1.LocalSubjectAccessReview{
					Action: authorizationv1.Action{Verb: "create", Resource: "policybindings"},
				}
				subjectAccessReviewTest{
					description:       "can I get a subjectaccessreview on myself even if I have no rights to do it generally",
					localInterface:    authorizationv1typedclient.NewForConfigOrDie(valerieClientConfig).LocalSubjectAccessReviews("openshift"),
					localReview:       askCanICreatePolicyBindings,
					kubeAuthInterface: kubernetes.NewForConfigOrDie(valerieClientConfig).AuthorizationV1(),
					response: authorizationv1.SubjectAccessReviewResponse{
						Allowed:   false,
						Reason:    ``,
						Namespace: "openshift",
					},
				}.run(t)

				askCanClusterAdminsCreateProject := &authorizationv1.LocalSubjectAccessReview{
					GroupsSlice: []string{"system:cluster-admins"},
					Action:      authorizationv1.Action{Verb: "create", Resource: "projects"},
				}
				subjectAccessReviewTest{
					description:       "I shouldn't be allowed to ask whether someone else can perform an action",
					localInterface:    authorizationv1typedclient.NewForConfigOrDie(valerieClientConfig).LocalSubjectAccessReviews("openshift"),
					localReview:       askCanClusterAdminsCreateProject,
					kubeAuthInterface: kubernetes.NewForConfigOrDie(valerieClientConfig).AuthorizationV1(),
					kubeNamespace:     "openshift",
					err:               `localsubjectaccessreviews.authorization.openshift.io is forbidden: User "` + valerieName + `" cannot create resource "localsubjectaccessreviews" in API group "authorization.openshift.io" in the namespace "openshift"`,
					kubeErr:           `localsubjectaccessreviews.authorization.k8s.io is forbidden: User "` + valerieName + `" cannot create resource "localsubjectaccessreviews" in API group "authorization.k8s.io" in the namespace "openshift"`,
				}.run(t)

			})
		})

		g.Describe("TestSelfSubjectAccessReviewsNonExistingNamespace", func() {
			g.It(fmt.Sprintf("should succeed [apigroup:user.openshift.io][apigroup:authorization.openshift.io]"), func() {
				t := g.GinkgoT()

				valerieName := oc.CreateUser("valerie-").Name
				valerieClientConfig := oc.GetClientConfigForUser(valerieName)

				// ensure that a SAR for a non-exisitng namespace gives a SAR response and not a
				// namespace doesn't exist response from admisison.
				askCanICreatePodsInNonExistingNamespace := &authorizationv1.LocalSubjectAccessReview{
					Action: authorizationv1.Action{Namespace: "foo", Verb: "create", Resource: "pods"},
				}
				subjectAccessReviewTest{
					description:       "ensure SAR for non-existing namespace does not leak namespace info",
					localInterface:    authorizationv1typedclient.NewForConfigOrDie(valerieClientConfig).LocalSubjectAccessReviews("foo"),
					localReview:       askCanICreatePodsInNonExistingNamespace,
					kubeAuthInterface: kubernetes.NewForConfigOrDie(valerieClientConfig).AuthorizationV1(),
					response: authorizationv1.SubjectAccessReviewResponse{
						Allowed:   false,
						Reason:    ``,
						Namespace: "foo",
					},
				}.run(t)
			})
		})
	})
})

var _ = g.Describe("[sig-auth][Feature:OpenShiftAuthorization] self-SAR with scoped tokens", func() {
	defer g.GinkgoRecover()
	oc := exutil.NewCLI("scoped-tokens")

	g.It(fmt.Sprintf("should succeed [apigroup:user.openshift.io][apigroup:authorization.openshift.io][apigroup:oauth.openshift.io]"), func() {
		t := g.GinkgoT()

		clusterAdminClientConfig := oc.AdminConfig()
		clusterAdminOAuthClient := oauthv1client.NewForConfigOrDie(clusterAdminClientConfig)
		client := &oauthv1.OAuthClient{
			ObjectMeta:  metav1.ObjectMeta{Name: "testing-client-" + oc.Namespace()},
			GrantMethod: oauthv1.GrantHandlerAuto,
		}
		if _, err := clusterAdminOAuthClient.OAuthClients().Create(context.Background(), client, metav1.CreateOptions{}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		oc.AddResourceToDelete(oauthv1.GroupVersion.WithResource("oauthclients"), client)

		user := oc.CreateUser("tokenuser-")
		oc.AddResourceToDelete(v1.GroupVersion.WithResource("users"), user)

		var createToken = func(tokenName string, scopes []string) *oauthv1.OAuthAccessToken {
			token := &oauthv1.OAuthAccessToken{
				ObjectMeta:  metav1.ObjectMeta{Name: tokenName},
				ClientName:  client.Name,
				UserName:    user.Name,
				UserUID:     string(user.UID),
				Scopes:      scopes,
				RedirectURI: "https://localhost:8443/oauth/token/implicit",
			}

			_, err := clusterAdminOAuthClient.OAuthAccessTokens().Create(context.Background(), token, metav1.CreateOptions{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			oc.AddResourceToDelete(oauthv1.GroupVersion.WithResource("oauthaccesstokens"), token)

			return token
		}

		tests := []struct {
			description    string
			token          string
			tokenObj       *oauthv1.OAuthAccessToken // TODO do I need the whole token object in the test?
			selfSARAllowed bool
		}{
			{
				"token has no user:check-access user:full or role scope",
				"sha256~cQCrXRpBdghJ9EjcHBJs3fAG8hhusl20B1YwZ_WwQF8",
				createToken("sha256~jwahvfqk7YeWkPkqTeOHJbKE4uDUqsoP1XhRHvk5--g", []string{"user:info", "user:list-projects"}),
				false,
			},
			{
				"token has user:check-access scope",
				"sha256~74nvCq63mA7c7fwkbqunvtoHv3i_4f_L3ToIX-vqEAg",
				createToken("sha256~nERCZRl1SLWsQJ1LO6uZqwtThWiMMWjhyOsCLEA10E8", []string{"user:check-access"}),
				true,
			},
			{
				"token has user:full scope",
				"sha256~3jWRPKDnhizSVdZEmAMbQaU6FKGr8O2XuJXG2utA4k8",
				createToken("sha256~44yteqXEA9zXAFifKmKyyiUwpOk5ZhUuUyd_s-WkNQY", []string{"user:full"}),
				true,
			},
			{
				"token has role scope",
				"sha256~RmcujdrsbNvRDl_-sEzp1sx6HbP-2ZlmFnvNY6rEN14",
				createToken("sha256~FlazKBhtre9nB0rnf_Tq1PB4b_7nI_a48H_K605x_f4", []string{"role:myrole:test"}), // TODO do I need to create this role?
				true,
			},
		}

		for range tests {
			// TODO use token to perform a self-SAR and assert expected result
		}
	})
})
