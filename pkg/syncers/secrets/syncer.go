package secrets

import (
	"fmt"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/loft-sh/vcluster-cert-manager-plugin/pkg/constants"
	"github.com/loft-sh/vcluster-sdk/syncer"
	"github.com/loft-sh/vcluster-sdk/syncer/context"
	"github.com/loft-sh/vcluster-sdk/syncer/translator"
	"github.com/loft-sh/vcluster-sdk/translate"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	IndexByCertificateSecret = "indexbycertificatesecret"
	IndexByIssuerSecret      = "indexbyissuersecret"
)

func New(ctx *context.RegisterContext) syncer.Base {
	return &secretSyncer{
		NamespacedTranslator: translator.NewNamespacedTranslator(ctx, "secret", &corev1.Secret{}),

		virtualClient:  ctx.VirtualManager.GetClient(),
		physicalClient: ctx.PhysicalManager.GetClient(),
	}
}

type secretSyncer struct {
	translator.NamespacedTranslator

	virtualClient  client.Client
	physicalClient client.Client
}

var _ syncer.IndicesRegisterer = &secretSyncer{}

func (s *secretSyncer) RegisterIndices(ctx *context.RegisterContext) error {
	err := ctx.VirtualManager.GetFieldIndexer().IndexField(ctx.Context, &certmanagerv1.Certificate{}, IndexByCertificateSecret, func(rawObj client.Object) []string {
		return secretNamesFromCertificate(rawObj.(*certmanagerv1.Certificate))
	})
	if err != nil {
		return err
	}
	err = ctx.VirtualManager.GetFieldIndexer().IndexField(ctx.Context, &certmanagerv1.Issuer{}, IndexByIssuerSecret, func(rawObj client.Object) []string {
		return secretNamesFromIssuer(rawObj.(*certmanagerv1.Issuer))
	})
	if err != nil {
		return err
	}

	return s.NamespacedTranslator.RegisterIndices(ctx)
}

var _ syncer.ControllerModifier = &secretSyncer{}

func (s *secretSyncer) ModifyController(ctx *context.RegisterContext, builder *builder.Builder) (*builder.Builder, error) {
	builder = builder.Watches(&source.Kind{Type: &certmanagerv1.Certificate{}}, handler.EnqueueRequestsFromMapFunc(mapCertificates))
	builder = builder.Watches(&source.Kind{Type: &certmanagerv1.Issuer{}}, handler.EnqueueRequestsFromMapFunc(mapIssuers))
	return builder, nil
}

func (s *secretSyncer) SyncDown(ctx *context.SyncContext, vObj client.Object) (ctrl.Result, error) {
	vSecret := vObj.(*corev1.Secret)
	createNeeded, err := s.isSecretUsed(ctx, vObj)
	if err != nil {
		return ctrl.Result{}, err
	} else if !createNeeded {
		return ctrl.Result{}, s.removeController(ctx, vSecret)
	}

	// switch controller
	switched, err := s.switchController(ctx, vSecret)
	if err != nil {
		return ctrl.Result{}, err
	} else if switched {
		return ctrl.Result{}, nil
	}

	// create the secret if it's needed
	return s.SyncDownCreate(ctx, vObj, s.translate(vObj.(*corev1.Secret)))
}

func (s *secretSyncer) Sync(ctx *context.SyncContext, pObj client.Object, vObj client.Object) (ctrl.Result, error) {
	vSecret := vObj.(*corev1.Secret)
	used, err := s.isSecretUsed(ctx, vObj)
	if err != nil {
		return ctrl.Result{}, err
	} else if !used {
		return ctrl.Result{}, s.removeController(ctx, vSecret)
	}

	// switch controller
	switched, err := s.switchController(ctx, vSecret)
	if err != nil {
		return ctrl.Result{}, err
	} else if switched {
		return ctrl.Result{}, nil
	}

	// update secret if necessary
	return s.SyncDownUpdate(ctx, vObj, s.translateUpdate(pObj.(*corev1.Secret), vObj.(*corev1.Secret)))
}

var _ syncer.UpSyncer = &secretSyncer{}

func (s *secretSyncer) SyncUp(ctx *context.SyncContext, pObj client.Object) (ctrl.Result, error) {
	// don't do anything here
	return ctrl.Result{}, nil
}

func (s *secretSyncer) removeController(ctx *context.SyncContext, vSecret *corev1.Secret) error {
	// remove us as owner
	if vSecret.Labels != nil && vSecret.Labels[translate.ControllerLabel] == constants.PluginName {
		delete(vSecret.Labels, translate.ControllerLabel)
		ctx.Log.Infof("update secret %s/%s because we the controlling party, but secret is not needed anymore", vSecret.Namespace, vSecret.Name)
		return ctx.VirtualClient.Update(ctx.Context, vSecret)
	}

	return nil
}

func (s *secretSyncer) switchController(ctx *context.SyncContext, vSecret *corev1.Secret) (bool, error) {
	// check if we own the secret
	if vSecret.Labels == nil || vSecret.Labels[translate.ControllerLabel] == "" {
		if vSecret.Labels == nil {
			vSecret.Labels = map[string]string{}
		}
		vSecret.Labels[translate.ControllerLabel] = constants.PluginName
		ctx.Log.Infof("update secret %s/%s because we are not the controlling party", vSecret.Namespace, vSecret.Name)
		return true, ctx.VirtualClient.Update(ctx.Context, vSecret)
	} else if vSecret.Labels[translate.ControllerLabel] != constants.PluginName {
		return true, nil
	}

	return false, nil
}

func (s *secretSyncer) isSecretUsed(ctx *context.SyncContext, vObj runtime.Object) (bool, error) {
	secret, ok := vObj.(*corev1.Secret)
	if !ok || secret == nil {
		return false, fmt.Errorf("%#v is not a secret", vObj)
	}

	certificateList := &certmanagerv1.CertificateList{}
	err := ctx.VirtualClient.List(ctx.Context, certificateList, client.MatchingFields{IndexByCertificateSecret: secret.Namespace + "/" + secret.Name})
	if err != nil {
		return false, err
	} else if meta.LenList(certificateList) > 0 {
		return true, nil
	}

	issuerList := &certmanagerv1.IssuerList{}
	err = ctx.VirtualClient.List(ctx.Context, issuerList, client.MatchingFields{IndexByIssuerSecret: secret.Namespace + "/" + secret.Name})
	if err != nil {
		return false, err
	} else if meta.LenList(issuerList) > 0 {
		return true, nil
	}

	return false, nil
}

func secretNamesFromCertificate(certificate *certmanagerv1.Certificate) []string {
	secrets := []string{}
	if certificate.Spec.Keystores != nil && certificate.Spec.Keystores.JKS != nil && certificate.Spec.Keystores.JKS.PasswordSecretRef.Name != "" {
		secrets = append(secrets, certificate.Namespace+"/"+certificate.Spec.Keystores.JKS.PasswordSecretRef.Name)
	}
	if certificate.Spec.Keystores != nil && certificate.Spec.Keystores.PKCS12 != nil && certificate.Spec.Keystores.PKCS12.PasswordSecretRef.Name != "" {
		secrets = append(secrets, certificate.Namespace+"/"+certificate.Spec.Keystores.PKCS12.PasswordSecretRef.Name)
	}
	return secrets
}

func mapCertificates(obj client.Object) []reconcile.Request {
	certificate, ok := obj.(*certmanagerv1.Certificate)
	if !ok {
		return nil
	}

	requests := []reconcile.Request{}
	names := secretNamesFromCertificate(certificate)
	for _, name := range names {
		splitted := strings.Split(name, "/")
		if len(splitted) == 2 {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: splitted[0],
					Name:      splitted[1],
				},
			})
		}
	}

	return requests
}

func secretNamesFromIssuer(issuer *certmanagerv1.Issuer) []string {
	secrets := []string{}
	if issuer.Spec.ACME != nil && issuer.Spec.ACME.PrivateKey.Name != "" {
		secrets = append(secrets, issuer.Namespace+"/"+issuer.Spec.ACME.PrivateKey.Name)
	}
	if issuer.Spec.CA != nil && issuer.Spec.CA.SecretName != "" {
		secrets = append(secrets, issuer.Namespace+"/"+issuer.Spec.CA.SecretName)
	}
	if issuer.Spec.Vault != nil && issuer.Spec.Vault.Auth.TokenSecretRef != nil && issuer.Spec.Vault.Auth.TokenSecretRef.Name != "" {
		secrets = append(secrets, issuer.Namespace+"/"+issuer.Spec.Vault.Auth.TokenSecretRef.Name)
	}
	if issuer.Spec.Venafi != nil && issuer.Spec.Venafi.TPP != nil && issuer.Spec.Venafi.TPP.CredentialsRef.Name != "" {
		secrets = append(secrets, issuer.Namespace+"/"+issuer.Spec.Venafi.TPP.CredentialsRef.Name)
	}
	if issuer.Spec.Venafi != nil && issuer.Spec.Venafi.Cloud != nil && issuer.Spec.Venafi.Cloud.APITokenSecretRef.Name != "" {
		secrets = append(secrets, issuer.Namespace+"/"+issuer.Spec.Venafi.Cloud.APITokenSecretRef.Name)
	}
	return secrets
}

func mapIssuers(obj client.Object) []reconcile.Request {
	issuer, ok := obj.(*certmanagerv1.Issuer)
	if !ok {
		return nil
	}

	requests := []reconcile.Request{}
	names := secretNamesFromIssuer(issuer)
	for _, name := range names {
		splitted := strings.Split(name, "/")
		if len(splitted) == 2 {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: splitted[0],
					Name:      splitted[1],
				},
			})
		}
	}

	return requests
}
