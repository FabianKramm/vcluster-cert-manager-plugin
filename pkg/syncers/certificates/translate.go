package certificates

import (
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/loft-sh/vcluster-sdk/translate"
	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (s *certificateSyncer) translate(vObj client.Object) *certmanagerv1.Certificate {
	pObj := s.TranslateMetadata(vObj).(*certmanagerv1.Certificate)
	vCertificate := vObj.(*certmanagerv1.Certificate)
	pObj.Spec = *rewriteSpec(&vCertificate.Spec, vCertificate.Namespace)
	return pObj
}

func (s *certificateSyncer) translateUpdate(pObj, vObj *certmanagerv1.Certificate) *certmanagerv1.Certificate {
	var updated *certmanagerv1.Certificate

	// check annotations & labels
	changed, updatedAnnotations, updatedLabels := s.TranslateMetadataUpdate(vObj, pObj)
	if changed {
		updated = newIfNil(updated, pObj)
		updated.Labels = updatedLabels
		updated.Annotations = updatedAnnotations
	}

	// update spec
	pSpec := rewriteSpec(&vObj.Spec, vObj.GetNamespace())
	if !equality.Semantic.DeepEqual(*pSpec, pObj.Spec) {
		updated = newIfNil(updated, pObj)
		updated.Spec = *pSpec
	}

	return updated
}

func rewriteSpec(vObjSpec *certmanagerv1.CertificateSpec, namespace string) *certmanagerv1.CertificateSpec {
	// translate secret names
	vObjSpec = vObjSpec.DeepCopy()
	if vObjSpec.SecretName != "" {
		vObjSpec.SecretName = translate.PhysicalName(vObjSpec.SecretName, namespace)
	}
	if vObjSpec.IssuerRef.Kind == "Issuer" {
		vObjSpec.IssuerRef.Name = translate.PhysicalName(vObjSpec.IssuerRef.Name, namespace)
	} else if vObjSpec.IssuerRef.Kind == "ClusterIssuer" {
		// TODO: rewrite ClusterIssuers
	}
	if vObjSpec.Keystores != nil && vObjSpec.Keystores.JKS != nil {
		vObjSpec.Keystores.JKS.PasswordSecretRef.Name = translate.PhysicalName(vObjSpec.Keystores.JKS.PasswordSecretRef.Name, namespace)
	}
	if vObjSpec.Keystores != nil && vObjSpec.Keystores.PKCS12 != nil {
		vObjSpec.Keystores.PKCS12.PasswordSecretRef.Name = translate.PhysicalName(vObjSpec.Keystores.PKCS12.PasswordSecretRef.Name, namespace)
	}

	return vObjSpec
}

func newIfNil(updated *certmanagerv1.Certificate, pObj *certmanagerv1.Certificate) *certmanagerv1.Certificate {
	if updated == nil {
		return pObj.DeepCopy()
	}
	return updated
}
