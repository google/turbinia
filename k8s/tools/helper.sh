# Setup some useful things
alias k=kubectl
# Apply a yaml file
alias kaf='kubectl apply -f'
# Delete a deployment
alias kdf='kubectl delete -f'
# Exec into a pod
alias ke='_ke(){ kubectl exec --stdin --tty $1 -- /bin/bash; unset -f _ke; }; _ke'
# Get pods
alias kgp='kubectl get pods'
# Get deployment
alias kgd='kubectl get deployment'
# Describe pods
alias kdp='kubectl describe pods'
# Get nodes
alias kgn='kubectl get nodes -o wide'
# Get logs
alias kl='kubectl logs'
alias kl1h='kubectl logs --since 1h'
alias kl1m='kubectl logs --since 1m'
alias kl1s='kubectl logs --since 1s'