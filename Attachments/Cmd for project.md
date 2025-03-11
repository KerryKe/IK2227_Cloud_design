# Cmd for project

## Basic

### Run kathara
cd Documents/ik2227-project

sudo kathara lstart --privilege

### Kubernet check
#### On controller1
kubectl get node

kubectl get pod -A

kubectl apply -f /shared/clustera/namespace.yaml

kubectl apply -f /shared/clustera/pvc.yaml

kubectl apply -f /shared/clustera/service.yaml

kubectl apply -f /shared/clustera/deployment.yaml

kubectl apply -f /shared/clustera/ingress.yaml

#### On controller2
kathara connect controller2

kubectl apply -f /shared/clusterb/namespace.yaml

kubectl apply -f /shared/clusterb/pvc.yaml

kubectl apply -f /shared/clusterb/service.yaml

kubectl apply -f /shared/clusterb/deployment.yaml

kubectl apply -f /shared/clusterb/ingress.yaml

#### On client_basic

curl -X POST -H "Content-Type: application/json" -d '{"query": "An orc wanted to destroy everything"}' http://clustera.com/completion

curl -X POST -H "Content-Type: application/json" -d '{"query": "An orc wanted to destroy everything"}' http://clusterb.com/completion

----



