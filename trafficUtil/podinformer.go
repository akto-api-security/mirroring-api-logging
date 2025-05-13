package trafficUtil

/*
The PodInformer module is a Kubernetes utility designed to watch and manage pod events.
(add, update, delete) on a specific node. It uses the Kubernetes client-go library to interact
with the Kubernetes API and maintain mappings of pod IPs and labels for efficient lookups.
*/

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	trafficUtils "github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	v1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

var KubeInjectEnabled = false
var PodInformerInstance *PodInformer

func init() {
	trafficUtils.InitVar("AKTO_K8_METADATA_CAPTURE", &KubeInjectEnabled)
}

type PodInformer struct {
	clientset    *kubernetes.Clientset
	nodeName     string
	ipPodMap     sync.Map
	podLabelsMap sync.Map
}

func equalPodIPs(a, b []corev1.PodIP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].IP != b[i].IP {
			return false
		}
	}
	return true
}

func SetupPodInformer() (chan struct{}, error) {
	if !KubeInjectEnabled {
		slog.Warn("AKTO_K8_METADATA_CAPTURE is not true, skipping PodInformer setup")
		return nil, nil
	}

	watcher, err := NewPodInformer()
	if err != nil {
		slog.Error("Failed to initialize pod watcher", "error", err)
		return nil, err
	}

	stopCh := make(chan struct{})
	// Start watching pods
	go func() {
		if err := watcher.WatchPods(stopCh); err != nil {
			slog.Error("Error watching pods", "error", err)
			return
		}
	}()

	PodInformerInstance = watcher
	return stopCh, nil
}

func GetClientset() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig for local testing
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create config: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}

	return clientset, nil
}

func NewPodInformer() (*PodInformer, error) {
	clientset, err := GetClientset()
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %v", err)
	}

	// Get the node name from the environment (set by Kubernetes for DaemonSet pods)
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return nil, fmt.Errorf("NODE_NAME environment variable not set")
	}
	return &PodInformer{
		clientset:    clientset,
		nodeName:     nodeName,
		ipPodMap:     sync.Map{},
		podLabelsMap: sync.Map{},
	}, nil
}

func (w *PodInformer) ResolveIPPodLabels(ip string) (string, error) {
	slog.Debug("Resolving IP to pod labels", "ip", ip)
	ip = strings.Split(ip, ":")[0]
	// Step 1: Find the IP key in ipPodMap
	podUID, ok := w.ipPodMap.Load(ip)
	if !ok {
		err := fmt.Errorf("pod informer failed to resolve ip %s", ip)
		slog.Error(err.Error())
		return "", err
	}

	// Step 2: Use the value (pod.UID) as the key to find labels in podLabelsMap
	labels, ok := w.podLabelsMap.Load(podUID)
	if !ok {
		err := fmt.Errorf("failed to resolve labels of pod uid: %s", podUID)
		slog.Error(err.Error())
		return "", err
	}

	// Step 3: Convert the labels (map[string]string) to a JSON string
	labelsMap, ok := labels.(map[string]string)
	if !ok {
		err := fmt.Errorf("invalid labels format for pod uid: %s", podUID)
		slog.Error(err.Error())
		return "", err
	}

	labelsJSON, err := json.Marshal(labelsMap)
	if err != nil {
		err := fmt.Errorf("failed to convert labels to JSON for pod uid: %s, error: %v", podUID, err)
		slog.Error(err.Error())
		return "", err
	}

	return string(labelsJSON), nil
}

func (w *PodInformer) logPodIPs() {
	var result string
	w.ipPodMap.Range(func(key, value interface{}) bool {
		result += fmt.Sprintf("IP: %s, Pod UID: %s; ", key, value)
		return true
	})
	slog.Debug("Pod IP Map", "map", result)
}

func (w *PodInformer) logPodLabels() {
	var result string
	w.podLabelsMap.Range(func(key, value interface{}) bool {
		result += fmt.Sprintf("Pod UID: %s, label: %s; ", key, value)
		return true
	})
	slog.Debug("Pod Labels Map", "map", result)
}

func (w *PodInformer) initPodIPMap(podInformer cache.SharedIndexInformer, podLister v1lister.PodLister) error {
	slog.Info("Initializing ipPod and podLabels maps")
	if !podInformer.HasSynced() {
		return fmt.Errorf("failed to wait for cache sync")
	}

	slog.Info("Pod watcher synced adding pods to ipPodMap")
	pods, err := podLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to List pods after syncing: %v", err)
	}

	for _, pod := range pods {
		for _, podIp := range pod.Status.PodIPs {
			w.ipPodMap.Store(podIp.IP, pod.UID)
		}
		w.podLabelsMap.Store(pod.UID, pod.Labels)
	}
	w.logPodIPs()
	w.logPodLabels()
	return nil
}

func (w *PodInformer) getFieldSelector() string {
	var namespaceFilter string
	nodeFilter := fmt.Sprintf("spec.nodeName=%s", w.nodeName)
	if os.Getenv("AKTO_K8_METADATA_CAPTURE_NAMESPACE") != "" {
		namespaceFilter = fmt.Sprintf("metadata.namespace=%s", os.Getenv("AKTO_K8_METADATA_CAPTURE_NAMESPACE"))
	} else {
		namespaceFilter = "metadata.namespace!=kube-system,metadata.namespace!=kube-public,metadata.namespace!=kube-node-lease"
	}
	return namespaceFilter + "," + nodeFilter
}

func (w *PodInformer) WatchPods(stopCh <-chan struct{}) error {

	informerFactory := informers.NewSharedInformerFactoryWithOptions(w.clientset, 20*time.Second, informers.WithTweakListOptions(func(fi *metav1.ListOptions) {
		fi.FieldSelector = w.getFieldSelector()
	}))

	podFactory := informerFactory.Core().V1().Pods()
	podInformer := podFactory.Informer()
	podLister := podFactory.Lister()

	slog.Info("Starting pod informer factory on", "node", w.nodeName)
	informerFactory.Start(stopCh)

	slog.Info("Waiting for pod informer cache sync")
	res := informerFactory.WaitForCacheSync(stopCh)
	slog.Info("Pod informer cache sync complete", "map", res)

	err := w.initPodIPMap(podInformer, podLister)
	if err != nil {
		return fmt.Errorf("failed to init pod ip and label maps: %v", err)
	}

	_, err = w.registerPodEventHandlers(podInformer)
	if err != nil {
		return fmt.Errorf("failed to register pod event handlers: %v", err)
	}

	return nil
}

func (w *PodInformer) registerPodEventHandlers(podInformer cache.SharedIndexInformer) (cache.ResourceEventHandlerRegistration, error) {
	slog.Info("Registering pod event handlers")
	handler, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.handlePodAdd,
		UpdateFunc: w.handlePodUpdate,
		DeleteFunc: w.handlePodDelete,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to register pod event handlers: %v", err)
	}
	slog.Info("Pod event handlers registered")
	return handler, err
}

func (w *PodInformer) handlePodAdd(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		slog.Error("Pod handler recived invalid", "pod", obj)
		return
	}
	slog.Debug("Pod added:", "namespace", pod.Namespace, "podName", pod.Name)
	for _, podIp := range pod.Status.PodIPs {
		w.ipPodMap.Store(podIp.IP, pod.UID)
	}
	w.podLabelsMap.Store(pod.UID, pod.Labels)
}

func (w *PodInformer) handlePodUpdate(oldObj, newObj interface{}) {
	oldPod, ok := oldObj.(*corev1.Pod)
	if !ok {
		slog.Error("Pod handler recived invalid", "pod", oldObj)
		return
	}
	newPod, ok := newObj.(*corev1.Pod)
	if !ok {
		slog.Error("Pod handler recived invalid", "pod", newObj)
		return
	}
	slog.Debug("Pod update:", "namespace", newPod.Namespace, "podName", newPod.Name)
	// TOOD potential bug, remove the oldIps from map ??
	// What comes in the update call, new IPs only or all the IPs ??
	if !equalPodIPs(oldPod.Status.PodIPs, newPod.Status.PodIPs) {
		for _, podIp := range newPod.Status.PodIPs {
			w.ipPodMap.Store(podIp.IP, newPod.UID)
		}
	}
	w.podLabelsMap.Delete(oldPod.UID)
	w.podLabelsMap.Store(newPod.UID, newPod.Labels)
}

func (w *PodInformer) handlePodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		slog.Error("Pod handler recived invalid", "pod", obj)
		return
	}
	slog.Debug("Pod update:", "namespace", pod.Namespace, "podName", pod.Name)
	for _, podIp := range pod.Status.PodIPs {
		w.ipPodMap.Delete(podIp.IP)
	}
	w.podLabelsMap.Delete(pod.UID)
}
