package kafkaUtil

/*
The PodInformer module is a Kubernetes utility designed to watch and manage pod events.
(add, update, delete) on a specific node. It uses the Kubernetes client-go library to interact
with the Kubernetes API and maintain mappings of pod IPs and labels for efficient lookups.
*/

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/akto-api-security/mirroring-api-logging/trafficUtil/utils"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	v1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

var KubeInjectEnabled = false

// TODO: Make this configurable, or account based.
var SERVICE_IDENTIFIER_LABELS = []string{"catalog.agoda.com/component", "privatecloud.agoda.com/service"}
var PodInformerInstance *PodInformer

type PodFileLog struct {
	hostCount      int
	cacheMissPods  map[string]int
	pids           map[int]int
	labelsCountMap map[string]int
}

var ReqHostLog = make(map[string]*PodFileLog)
var reqHostPodResolutionLog strings.Builder

func logReqHostPodResolution(reqHost string, labelsJson string, pid int, podHostName string) {
	podfileLog, exists := ReqHostLog[reqHost]
	if !exists {
		podfileLog = &PodFileLog{
			hostCount:      0,
			cacheMissPods:  make(map[string]int),
			pids:           make(map[int]int),
			labelsCountMap: make(map[string]int),
		}
	}
	podfileLog.hostCount++
	if labelsJson == "" {
		podfileLog.cacheMissPods[podHostName]++
	} else {
		var labelsMap map[string]string
		if err := json.Unmarshal([]byte(labelsJson), &labelsMap); err == nil {
			for labelName, value := range labelsMap {
				if slices.Contains(SERVICE_IDENTIFIER_LABELS, labelName) {
					podfileLog.labelsCountMap[labelName+":"+value]++
				}
			}
		} else {
			slog.Error("Failed to unmarshal labels JSON", "error", err)
		}
		reqHostPodResolutionLog.WriteString(fmt.Sprintf("reqHost: %s,\t labels: %s, \t pid: %d, podHostName: %s\n", reqHost, labelsJson, pid, podHostName))
	}
	podfileLog.pids[pid]++
	ReqHostLog[reqHost] = podfileLog
}

func init() {
	utils.InitVar("AKTO_K8_METADATA_CAPTURE", &KubeInjectEnabled)
	reqHostPodResolutionLog.WriteString("reqHost\tlabelsCount\tpidCount\tcacheMisspodHostName\n")
}

type PodInformer struct {
	clientset        *kubernetes.Clientset
	nodeName         string
	podNameLabelsMap sync.Map // Maps pod names to their labels directly
	pidHostNameMap   map[int32]string
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
	watcher.BuildPidHostNameMap()
	slog.Info("PodInformer initialized successfully", "nodeName", watcher.nodeName)

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
	// this works when the pod has service accounts with proper rbac role attached
	config, err := rest.InClusterConfig()
	// this is used for out of cluster configuration
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
		clientset:        clientset,
		nodeName:         nodeName,
		podNameLabelsMap: sync.Map{},
		pidHostNameMap:   make(map[int32]string),
	}, nil
}

func (w *PodInformer) GetPodNameByProcessId(pid int32) string {
	if hostName, ok := w.pidHostNameMap[pid]; ok {
		slog.Debug("Hostname env found for", "processId", pid, "hostName", hostName)
		return hostName
	}
	slog.Warn("Hostname not found for", "processId", pid)
	return ""
}

func (w *PodInformer) BuildPidHostNameMap() {

	cmd := exec.Command("sh", "-c", "for dir in /host/proc/[0-9]*; do pid=$(echo \"$dir\" | cut -d'/' -f4); if [ -f \"$dir/environ\" ]; then hostname=$(strings \"$dir/environ\" | grep '^HOSTNAME=' | cut -d'=' -f2); if [ -n \"$hostname\" ]; then echo \"$pid $hostname\"; fi; fi; done")
	output, err := cmd.Output()
	if err != nil {
		slog.Error("Failed to execute shell command", "error", err)
		return
	}
	slog.Debug("Shell command output for PID to Hostname mapping", "output", string(output))
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			pid, err := strconv.Atoi(parts[0])
			if err == nil {
				w.pidHostNameMap[int32(pid)] = parts[1]
			}
		}
	}
	slog.Info("PID to Hostname map built successfully", "map", w.pidHostNameMap)
	w.logPidHostNameMap()
}

func (w *PodInformer) ResolvePodLabels(podName string, url, reqHost string) (string, error) {
	slog.Debug("Resolving Pod Name to labels", "podName", podName)
	checkDebugUrlAndPrint(url, reqHost, "Resolving Pod Name to labels for "+podName)

	// Step 1: Use the pod name as the key to find labels in podNameLabelsMap
	// Hostname captured from PID has the format clusterName-nodeName-podName
	// But the podLabelsMap is stored with just the podName, hence we check for suffix match.

	var labelsMap map[string]string
	w.podNameLabelsMap.Range(func(k8PodName, labels interface{}) bool {
		if strings.HasSuffix(podName, k8PodName.(string)) {
			labelsMap = labels.(map[string]string)
			return false // stop iteration
		}
		return true // continue iteration
	})

	if len(labelsMap) == 0 {
		err := fmt.Errorf("pod labels cache miss for pod name: %s", podName)
		checkDebugUrlAndPrint(url, reqHost, err.Error())
		return "", err
	}

	labelsJSON, err := json.Marshal(labelsMap)
	if err != nil {
		err := fmt.Errorf("failed to convert labels to JSON for pod name: %s, error: %v", podName, err)
		return "", err
	}

	return string(labelsJSON), nil
}

func (w *PodInformer) logPidHostNameMap() {
	slog.Warn("Logging PID to Hostname Map to file", "file", utils.GoPidLogFile)
	var builder strings.Builder
	fmt.Fprintf(&builder, "PID\tHostname:\n")

	for pid, hostName := range w.pidHostNameMap {
		fmt.Fprintf(&builder, "%d\t%s\n", pid, hostName)
	}
	fmt.Fprintf(&builder, "-------Total PIDs tracked: %d----------\n", len(w.pidHostNameMap))
	utils.LogToSpecificFile(utils.GoPidLogFile, builder.String())
	slog.Warn("PID to Hostname Map logged", "map", w.pidHostNameMap)
}

func (w *PodInformer) logPodLabelsMapFile() {
	var builder strings.Builder
	fmt.Fprintf(&builder, "PodName\tLabels:\n")

	w.podNameLabelsMap.Range(func(key, value interface{}) bool {
		labelsMap, _ := value.(map[string]string)

		// For each pod, we only log the labels that are in SERVICE_IDENTIFIER_LABELS
		var labelString strings.Builder
		for labelName, value := range labelsMap {
			if slices.Contains(SERVICE_IDENTIFIER_LABELS, labelName) {
				labelString.WriteString(fmt.Sprintf("%s=%s, ", labelName, value))
			}
		}
		fmt.Fprintf(&builder, "%s\t%s\n", key, labelString.String())
		return true
	})
	utils.LogToSpecificFile(utils.LabelsMapLogFile, builder.String())
}

func (w *PodInformer) logPodNameLabelsMap() {
	var result string
	w.podNameLabelsMap.Range(func(key, value interface{}) bool {
		result += fmt.Sprintf("Name: %s, Labels: %s; ", key, value)
		return true
	})
	slog.Warn("Pod Name Labels Map", "map", result)
	w.logPodLabelsMapFile()
}

func (w *PodInformer) initpodNameLabelsMap(podInformer cache.SharedIndexInformer, podLister v1lister.PodLister) error {
	slog.Warn("Initializing podNameLabels map")
	if !podInformer.HasSynced() {
		return fmt.Errorf("failed to wait for cache sync")
	}

	slog.Warn("Pod watcher synced adding pods to podNameLabelsMap")
	pods, err := podLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to List pods after syncing: %v", err)
	}

	for _, pod := range pods {
		w.podNameLabelsMap.Store(pod.Name, pod.Labels)
		ProducePodMapping(context.Background(), pod.Name)
	}
	w.logPodNameLabelsMap()
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

	informerFactory := informers.NewSharedInformerFactoryWithOptions(w.clientset, 60*time.Second, informers.WithTweakListOptions(func(fi *metav1.ListOptions) {
		fi.FieldSelector = w.getFieldSelector()
	}))

	podFactory := informerFactory.Core().V1().Pods()
	podInformer := podFactory.Informer()
	podLister := podFactory.Lister()

	slog.Warn("Starting pod informer factory on", "node", w.nodeName)
	informerFactory.Start(stopCh)

	slog.Warn("Waiting for pod informer cache sync")
	res := informerFactory.WaitForCacheSync(stopCh)
	slog.Warn("Pod informer cache sync complete", "map", res)

	err := w.initpodNameLabelsMap(podInformer, podLister)
	if err != nil {
		return fmt.Errorf("failed to init pod name and label maps: %v", err)
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

// node, pod, daemonset, lastSyncTime
// node, podId, daemonset, lastSyncTime
func (w *PodInformer) handlePodAdd(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		slog.Error("Pod handler received invalid", "pod", obj)
		return
	}
	slog.Debug("Pod added:", "namespace", pod.Namespace, "podName", pod.Name)
	w.podNameLabelsMap.Store(pod.Name, pod.Labels)
	// Build the PID to Hostname map again to ensure it is up-to-date
	// TODO: Optimize this ? What's the rate of pod add events?
	w.BuildPidHostNameMap()
	go ProducePodMapping(context.Background(), pod.Name)
}

func (w *PodInformer) handlePodUpdate(oldObj, newObj interface{}) {
	oldPod, ok := oldObj.(*corev1.Pod)
	if !ok {
		slog.Error("Pod handler received invalid", "pod", oldObj)
		return
	}
	newPod, ok := newObj.(*corev1.Pod)
	if !ok {
		slog.Error("Pod handler received invalid", "pod", newObj)
		return
	}
	slog.Debug("Pod update:", "namespace", newPod.Namespace, "podName", newPod.Name)
	w.podNameLabelsMap.Delete(oldPod.Name)
	w.podNameLabelsMap.Store(newPod.Name, newPod.Labels)
}

func (w *PodInformer) handlePodDelete(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		slog.Error("Pod handler received invalid", "pod", obj)
		return
	}
	slog.Debug("Pod deleted:", "namespace", pod.Namespace, "podName", pod.Name)
	w.podNameLabelsMap.Delete(pod.Name)
	// Build the PID to Hostname map again to ensure it is up-to-date
	// TODO: Optimize this ? What's the rate of pod add events?
	w.BuildPidHostNameMap()
}
