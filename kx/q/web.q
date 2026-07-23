.util.logm"Connect here: ","/"sv("http:/";":"sv string(.z.h;system"p");"index.html")

// Server-trusted session map: websocket handle -> authenticated userid.
// The client can never set this; every data handler derives identity from it.
.web.sessions:()!()
// Failed auth attempts per handle (reset on success or disconnect)
.web.authFails:()!()
// One-time HTTP download tokens: token(sym) -> (fileid;userid;expiry)
.web.downloadTokens:()!()
// Chunked uploads in progress: fileid(sym) -> metadata dict (see startUpload)
.web.uploadSessions:()!()

// userid bound to the current handle, or signal if the caller isn't authenticated
.web.currentUser:{$[.z.w in key .web.sessions; .web.sessions .z.w; '"not authenticated"]}

// Whitelisted dispatch: only these functions are reachable from the socket.
// Prevents arbitrary q execution from client-supplied `func` strings.
.web.allowed:`authUser`recentUploadsForUser`startUpload`uploadChunk`finishUpload`getDownloadToken`deleteFile`getSystemStats`deviceInfo
process:{[op]
  f:`$op`func;
  if[not f in .web.allowed;'"unknown function: ",string f];
  (value f) op`params
 }

.web.userMsg:{[level;head;body] (`notifyUser;`category`head`body!(level;head;body))}
//HANDLERS
/when a websocket connection is made, add the info to our live dailyConns table
.z.wo:{
 .util.logm"Websocket connection established with user";
 .util.ammend[`dailyConns;(.z.w;`event`sessionStart`sessionEnd`ip);(`open;.z.P;0Np;.util.za2ip[.z.a])];
 .util.logm"Available user information added to dailyConns table";
 }
 /when a websocket connection is made, add the info to our live dailyConns table
.z.wc:{
 .util.logm"Websocket connection closed with user handle: ",string[x];
 .util.ammend[`dailyConns;(x;`event`sessionEnd`ip);(`close;.z.P;.util.za2ip[.z.a])];
 .util.logm"Copying session's conn info from dailyConns to dailySessions";
 `dailySessions upsert `userid xcols 0!delete event from select from dailyConns where handle=x;
 .util.persist[`dailySessions];
 .web.cleanupOrphanedUploads[$[x in key .web.sessions;.web.sessions x;`]];
 .web.sessions:.web.sessions _ x;
 .web.authFails:.web.authFails _ x;
 updUserNumUsers[];
 }

// Drop any chunked-upload sessions the disconnecting user never finished (e.g. tab closed mid-upload)
.web.cleanupOrphanedUploads:{[uid]
 if[null uid; :()];
 fids:key .web.uploadSessions;
 if[0=count fids; :()];
 orphaned:fids where uid=value .web.uploadSessions[;`userid];
 {.[hdel;enlist hsym `$.config.ENV[`BLACKBOX_VAULT_DIR],"/",string x;{[p;e] .util.logm"Orphaned upload vault file already absent: ",p}[string x]]}each orphaned;
 .web.uploadSessions:.web.uploadSessions _ orphaned;
 }

.z.ws:{
 .util.logm"Message recieved from user at handle ",sh:string[.z.w];
 st:.z.T;
 op:.j.k -9!x;
 err:{(`Error;"Error in function. ERROR==>'",x)};
 res:$[.config.DEVMODE;process[op];@[process;op;err]];
 tm:string[tt:.z.T-st];
 neg[.z.w][-8!.j.j res,enlist tm];
 .util.logm"Response sent back through handle ",sh,". Time taken: ",tm;
 }

//===============================NATIVE HTTP DOWNLOAD===========================//
// Preserve kdb+'s built-in static file server (serves .h.HOME) for every path
// except our own download route.
.web.defaultph:.z.ph
.z.ph:{[x]
 $[(first x) like "download?*"; .web.serveDownload first x; .web.defaultph x]
 }

.web.httpResponse:{[status;ctype;body]
 "HTTP/1.1 ",status,"\r\nContent-Type: ",ctype,"\r\nContent-Length: ",string[count body],"\r\nConnection: close\r\n\r\n",body
 }

.web.parseQuery:{[path]
 q:1_(path?"?")_path;
 $[0=count q; ()!(); (`$first each kvs)!last each kvs:"=" vs/: "&" vs q]
 }

// Serve the vault ciphertext for a single-use, short-lived token minted by getDownloadToken.
// The token proves ownership was already checked over the authenticated websocket session -
// plain HTTP has no session of its own here, so the token stands in for one.
.web.serveDownload:{[path]
 q:.web.parseQuery path;
 tok:`$q`token;
 fid:`$q`fileid;
 if[not tok in key .web.downloadTokens; :.web.httpResponse["404 Not Found";"text/plain";"Invalid or expired download link"]];
 rec:.web.downloadTokens tok;
 .web.downloadTokens:.web.downloadTokens _ tok;
 if[not (rec 0)~fid; :.web.httpResponse["403 Forbidden";"text/plain";"Token/file mismatch"]];
 if[.z.P > rec 2; :.web.httpResponse["403 Forbidden";"text/plain";"Download link expired"]];

 fpth:.config.ENV[`BLACKBOX_VAULT_DIR],"/",string fid;
 body:first read0 hsym `$fpth;
 .web.httpResponse["200 OK";"text/plain";body]
 }
