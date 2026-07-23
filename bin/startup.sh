#!/bin/bash
echo Reinitialising BlackBox environment
export BLACKBOX_PORT="50667"
export BLACKBOX_KX_HOME=$BLACKBOX_HOME/kx
export BLACKBOX_Q_SCRIPT_DIR=$BLACKBOX_HOME/kx/q
export BLACKBOX_DB_DIR=$BLACKBOX_HOME/kx/db/qdb
export BLACKBOX_VAULT_DIR=$BLACKBOX_HOME/kx/db/vault
export BLACKBOX_USER_CONFIG=$BLACKBOX_HOME/kx/db/misc/users
export BLACKBOX_HTML_DIR=$BLACKBOX_HOME/html
echo Done - starting blackbox q server in devmode
rlwrap $QHOME/m64/q $BLACKBOX_Q_SCRIPT_DIR/starter.q -dev
