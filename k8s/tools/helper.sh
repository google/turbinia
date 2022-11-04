# Setup some useful things
alias k=kubectl
# Apply a yaml file
alias kaf='kubectl apply -f'
# Exec into a pod
alias ke='_ke(){ kubectl exec --stdin --tty $1 -- /bin/bash; unset -f _ke; }; _ke'
# Get logs
alias kl='kubectl logs'
alias kl1h='kubectl logs --since 1h'
alias kl1m='kubectl logs --since 1m'
alias kl1s='kubectl logs --since 1s'
# Get resources
alias kgp='kubectl get pods'
alias kgd='kubectl get deployment'
alias kgs='kubectl get svc'
alias kgi='kubectl get ingress'
alias kgn='kubectl get nodes -o wide'
# Describe resources
alias kdp='kubectl describe pods'
alias kdd='kubectl describe deployment'
alias kds='kubectl describe svc'
alias kdi='kubectl describe ingress'
# Delete resources
alias kdf='kubectl delete -f'
alias kdeld='kubectl delete deployment'
alias kdelcm='kubectl delete configmap'
alias kdels='kubectl delete svc'
alias kdeli='kubectl delete ingress'
# Restart resources
alias krrd='kubectl rollout restart deployment'
alias krrp='kubectl rollout restart pod'
alias krrs='kubectl rollout restart svc'