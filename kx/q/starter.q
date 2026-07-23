//==============================INITIALISATION================================//
k).util.logm:{-1@" - "/:("@"/:$(x;y);$.z.P;z);}[.z.u;.z.h;]
.config.DEVMODE:`dev in key .Q.opt[.z.x]
/let us take a moment to think about whether we have everything setup on our end
if[not .config.DEVMODE;
   .ts.i:0;while[.ts.i<10;;system["sleep 0.5"];2@".";.ts.i+:1;];];
.util.logm"Initialising BlackBox";
/predefine the required env vars
.config.ENVVARS:`BLACKBOX_DB_DIR`BLACKBOX_HTML_DIR,
                `BLACKBOX_KX_HOME`BLACKBOX_Q_SCRIPT_DIR,
                `BLACKBOX_VAULT_DIR`BLACKBOX_HOME,
                `BLACKBOX_PORT`BLACKBOX_USER_CONFIG
/parse the system env vars that are associated with the blackbox system
.config.ENV:(!). ("S*";"=")0:system["env"]where(system"env")like\:"BLACKBOX*"

/ base64-encoded per-file ceiling; cap total vault storage per file
.config.MAXUPLOAD:2*1024*1024*1024
.config.MAXFAILS:5
/ startUpload rejects new uploads once the vault filesystem's free space drops below this
/ percentage - see .util.diskStats/startUpload in blackbox.q
.config.MIN_DISK_HEADROOM_PCT:5
/normal load for DEVMODE
.util.devload:{[kpath] system"l ",kpath;}
/safe eval for non DEVMODE
.util.safeload:{[kpath]
 @[system;"l ",kpath;{.util.logm"Couldn't load script: ",x," - ERROR: '",y;exit 1;}[kpath;];];
 }
/chose whether to load safetly or not
.util.loadk:.util[`safeload`devload].config.DEVMODE
/if env vars missing print out and throw error if edbug - otherwise exit
if[not(asc .config.ENVVARS)~asc key .config.ENV;
   .util.logm"ENV NOT CONFIGURED:",", "sv string .config.ENVVARS except .config.ENVVARS inter key .config.ENV;
   $[.config.DEVMODE;[.util.logm"Exiting...";exit 1];'"DEVMODE"];];
.util.logm"Enviornment is configured. Configuring process for startup"
.h.HOME:.config.ENV[`BLACKBOX_HTML_DIR]
//=================================STARTUP====================================//
.config.configure:{
 .util.logm"Opening port number: ",pn:.config.ENV[`BLACKBOX_PORT];
 system["p ",pn];
 {{@[system;"mkdir -p ",x;()]}each 1_'string .Q.dd[x;]each f where not(f:`misc`qdb`vault)in\:key x}hsym`$.config.ENV[`BLACKBOX_KX_HOME],"/db";
 .util.logm"Loading data from kdb database";
 .util.loadk[.config.ENV[`BLACKBOX_DB_DIR]];
 .util.logm"Loading scripts as:",", "sv qcode:string`util.q`web.q`blackbox.q;
 .util.loadk each(.config.ENV[`BLACKBOX_Q_SCRIPT_DIR],"/"),/:qcode;
 .util.logm"BlackBox is now live";
 }
$[.config.DEVMODE;
  [.config.configure[];system["e 1"];system["c 20 140"];if[.z.o like "m*";system"/usr/bin/open -a Google\\ Chrome http://localhost:50667/index.html";]];
  @[.config.configure;();{.util.logm"Failed to start BlackBox - ERROR:'",x;exit 1}]];

