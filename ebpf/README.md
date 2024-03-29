

## To build the module:

```bash
docker buildx build --platform=linux/amd64 -t <username>/ebpf:v1  -f Dockerfile.eBPF
docker push <username>/ebpf:v1
```

## To deploy the module

Change the image name accordingly in the daemonset.
Add correct values for kafka and mongo IPs. The module will not process anything, if it cannot connect to them.
A node selector is being used to target specific nodes only. You can modify the same to your use case.
Tune the env variables to your specific use cases
```bash
kubectl apply -f daemonset-ebpf.yml -n bookinfo
```
To redeploy, either build/push an image with a new tag and apply the daemonset file again. or build/push the same tag and delete the existing pod [It pulls the latest image] .

## To see the logs and open shell in the daemonset

```bash
kubectl logs <pod-name> -n bookinfo --tail 10 -f
kubetl exec -it <pod-name> -n bookinfo sh
```

## To print bpf trace

```bash
cat /sys/kernel/debug/tracing/trace_pipe
```

### To load test [ test-load-server setup in sandbox-mumbai], check the previous commands.
Either a "postman-token" header or /productpage/< id > is used to check for matching req-res

### Istio server is running a custom go echo module, currently. If need be, the same can be be changed easily.

### Debug statements req-res checks are present in eventCallbacks.go and parser.go