package certificates

import (
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/loft-sh/vcluster-sdk/syncer"
	"github.com/loft-sh/vcluster-sdk/syncer/context"
	"github.com/loft-sh/vcluster-sdk/syncer/translator"
	"github.com/loft-sh/vcluster-sdk/translate"
	"k8s.io/apimachinery/pkg/api/equality"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func New(ctx *context.RegisterContext) syncer.Syncer {
	return &certificateSyncer{
		NamespacedTranslator: translator.NewNamespacedTranslator(ctx, "certificate", &certmanagerv1.Certificate{}),
	}
}

type certificateSyncer struct {
	translator.NamespacedTranslator
}

var _ syncer.Initializer = &certificateSyncer{}

func (s *certificateSyncer) Init(ctx *context.RegisterContext) error {
	return translate.EnsureCRDFromPhysicalCluster(ctx.Context, ctx.PhysicalManager.GetConfig(), ctx.VirtualManager.GetConfig(), certmanagerv1.SchemeGroupVersion.WithKind("Certificate"))
}

func (s *certificateSyncer) SyncDown(ctx *context.SyncContext, vObj client.Object) (ctrl.Result, error) {
	return s.SyncDownCreate(ctx, vObj, s.translate(vObj.(*certmanagerv1.Certificate)))
}

func (s *certificateSyncer) Sync(ctx *context.SyncContext, pObj client.Object, vObj client.Object) (ctrl.Result, error) {
	vCertificate := vObj.(*certmanagerv1.Certificate)
	pCertificate := pObj.(*certmanagerv1.Certificate)

	if !equality.Semantic.DeepEqual(vCertificate.Status, pCertificate.Status) {
		newIssuer := vCertificate.DeepCopy()
		newIssuer.Status = pCertificate.Status
		ctx.Log.Infof("update virtual certificate %s/%s, because status is out of sync", vCertificate.Namespace, vCertificate.Name)
		err := ctx.VirtualClient.Status().Update(ctx.Context, newIssuer)
		if err != nil {
			return ctrl.Result{}, err
		}

		// we will requeue anyways
		return ctrl.Result{}, nil
	}

	// did the certificate change?
	return s.SyncDownUpdate(ctx, vObj, s.translateUpdate(pCertificate, vCertificate))
}
