# Setup some usefull things
alias k=kubectl
ke() { kubectl exec --stdin --tty $1 -- /bin/bash; }
export ke
