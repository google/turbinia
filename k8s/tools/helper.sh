# Setup some useful things
alias k=kubectl
ke() { kubectl exec --stdin --tty $1 -- /bin/bash; }
export ke
