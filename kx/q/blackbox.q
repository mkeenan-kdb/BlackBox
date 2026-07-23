//===================================CONFIG===================================//
dailyConnsTemplate:dailyConns:([handle:0#0Ni]
  userid:0#`;
  event:0#`;
  ip:();
  sessionStart:0#0Np;
  sessionEnd:0#0Np)
dailySessionsTemplate:`userid xcols 0!delete event from dailyConns
// Only initialise session history if it wasn't loaded from disk (persisted on disconnect)
if[not `dailySessions in key `.; dailySessions:dailySessionsTemplate];

// Initialize uploads table if not present on disk
if[not `uploads in key `.;
  uploads:([fileid:0#`g]
    userid:0#`;
    fileName:();
    mimeType:();
    category:0#`;
    tags:();
    uploadDate:0#0Np;
    fileSize:0#0Nj;
    iv:();
    salt:());
  ];

// Ensure userinfo carries a per-user salt column (legacy rows load without one)
if[`userinfo in key `.;
  if[not `salt in cols userinfo; userinfo:1!update salt:(count i)#enlist"" from 0!userinfo]];

//===================================LOGIC====================================//
broadCast:{neg[x]@\:y;}

recentUploadsForUser:{[params]
  / Only ever return the authenticated caller's own metadata
  uid:.web.currentUser[];
  res:select string fileid, fileName, mimeType, category, tags, uploadDate, fileSize from uploads where userid=uid;
  :("recentUploads";res);
 }

deviceInfo:{
  .mk.d:x;
  show x;
 }

/ Begin a chunked upload: validate the declared size, allocate a fileid, and
/ stash metadata until every chunk has landed via uploadChunk/finishUpload.
startUpload:{[params]
  uid:.web.currentUser[];
  fileSize:"j"$params`fileSize;
  if[.config.MAXUPLOAD < fileSize; :("Error";"File exceeds the maximum allowed size")];

  fid:`$string first neg[1]?0Ng;
  .web.uploadSessions[fid]:`userid`fileName`mimeType`category`tags`iv`salt`bytesWritten!(
    uid;params`fileName;params`mimeType;`$params`category;params`tags;params`iv;params`salt;0);
  .util.logm"Chunked upload started by ",string[uid]," for ",params[`fileName]," -> ",string fid;
  :("uploadStarted";(enlist`fileid)!enlist string fid);
 }

/ Append one chunk of already-encrypted, base64-encoded data to the vault file.
uploadChunk:{[params]
  uid:.web.currentUser[];
  fid:`$params`fileid;
  if[not fid in key .web.uploadSessions; :("Error";"Unknown or expired upload session")];
  sess:.web.uploadSessions fid;
  if[not sess[`userid]~uid; :("Error";"Not authorised for this upload")];

  chunk:params`chunkData;
  bw:sess[`bytesWritten]+count chunk;
  fpth:.config.ENV[`BLACKBOX_VAULT_DIR],"/",string fid;
  if[bw > .config.MAXUPLOAD;
    .[hdel;enlist hsym `$fpth;{[p;e] .util.logm"Vault file already absent: ",p}[fpth]];
    .web.uploadSessions:.web.uploadSessions _ fid;
    :("Error";"File exceeds the maximum allowed size")];

  h:hopen hsym `$fpth;
  h chunk;
  hclose h;
  .web.uploadSessions[fid;`bytesWritten]:bw;
  :("chunkAck";`fileid`bytesWritten!(string fid;bw));
 }

/ Finalise a chunked upload once every chunk has been written: record the metadata row.
finishUpload:{[params]
  uid:.web.currentUser[];
  fid:`$params`fileid;
  if[not fid in key .web.uploadSessions; :("Error";"Unknown or expired upload session")];
  sess:.web.uploadSessions fid;
  if[not sess[`userid]~uid; :("Error";"Not authorised for this upload")];

  `uploads upsert 1!enlist `fileid`userid`fileName`mimeType`category`tags`uploadDate`fileSize`iv`salt!(
    fid;uid;sess`fileName;sess`mimeType;sess`category;sess`tags;.z.P;sess`bytesWritten;sess`iv;sess`salt);
  .util.persist[`uploads];
  .web.uploadSessions:.web.uploadSessions _ fid;
  .util.logm"Chunked upload finished for ",string[uid]," -> ",string fid;
  :("uploadSuccess";sess`fileName);
 }

/ Issue a short-lived, single-use token so the browser can fetch ciphertext over a
/ plain HTTP GET (see .z.ph in web.q) instead of round-tripping it through JSON/websocket.
getDownloadToken:{[params]
  uid:.web.currentUser[];
  fid:`$params`fileid;
  rec:uploads[fid];
  if[null rec`userid; :("Error";"File not found");];
  if[not rec[`userid]~uid; :("Error";"Not authorised to access this file");];

  tok:`$.util.newSalt[];
  .web.downloadTokens[tok]:(fid;uid;.z.P+0D00:02:00);
  :("downloadToken";`fileid`token`fileName`mimeType`iv`salt!(
    string fid;
    string tok;
    rec`fileName;
    rec`mimeType;
    rec`iv;
    rec`salt
  ));
 }

deleteFile:{[params]
  uid:.web.currentUser[];
  fid:`$params`fileid;
  rec:uploads[fid];
  if[null rec`userid; :("Error";"File not found");];
  if[not rec[`userid]~uid; :("Error";"Not authorised to delete this file");];

  / Remove the ciphertext from the vault (tolerate an already-missing file)
  fpth:.config.ENV[`BLACKBOX_VAULT_DIR],"/",string fid;
  .[hdel;enlist hsym `$fpth;{[p;e] .util.logm"Vault file already absent: ",p}[fpth]];

  `uploads set 1!delete from 0!uploads where fileid=fid;
  .util.persist[`uploads];
  .util.logm"Deleted file ",string[fid]," for ",string uid;
  :("deleteSuccess";string fid);
 }

getSystemStats:{[params]
  uid:.web.currentUser[];
  totalSize:exec sum fileSize from uploads where userid=uid;
  / 64GB simulated capacity
  capacity:68719476736;
  :("systemStats";`used`capacity!(0^totalSize;capacity));
 }

updUserNumUsers:{
  active:exec i from dailyConns where not null userid,event=`open,not null sessionStart,null sessionEnd;
  numusers:count active;
  msg:-8!.j.j(`numUsers;(enlist`numusers)!enlist numusers),enlist string[.z.T];
  .util.logm"Broadcasting message to ",string[numusers]," connected users";
  broadCast[(exec handle from dailyConns)active;msg];
 }

/addUser `userid`passphrase!("myUser";"myPassword")
addUser:{
  uid:`$x`userid;
  salt:.util.newSalt[];
  .util.logm"Adding new user: ",string uid;
  .util.putUser[uid;.util.hashPass[salt;x`passphrase];salt];
 }

/pull the user credentials from disk and ensure userid and pw match
authUser:{[creds]
  .util.logm"Requesting authentication for handle: ",string[.z.w];
  if[any all@/:null creds;:("authResp";0b);];
  if[not`userinfo in key`.;:("authResp";0b)];

  / Rate limit brute-force attempts per handle
  fails:$[.z.w in key .web.authFails; .web.authFails .z.w; 0];
  if[fails>=.config.MAXFAILS; .util.logm"Auth attempts exceeded on handle ",string[.z.w]; :("authResp";0b);];

  uid:`$creds`userid;
  pass:creds`pass;
  exists:uid in exec userid from userinfo;
  ok:0b; legacy:0b;
  if[exists;
    rec:userinfo uid;
    / A record with an empty salt predates salted hashing (legacy unsalted md5)
    legacy:0=count rec`salt;
    ok:$[legacy; rec[`passphrase]~raze string md5 pass;
         rec[`passphrase]~.util.hashPass[rec`salt;pass]]];

  / Transparently upgrade a legacy hash to the salted scheme on first good login
  if[ok and legacy;
     salt:.util.newSalt[];
     .util.putUser[uid;.util.hashPass[salt;pass];salt];
     .util.logm"Upgraded password hash for ",string uid];

  $[ok;
    [ .web.sessions[.z.w]:uid;
      .web.authFails:.web.authFails _ .z.w;
      updkols:`userid`event`ip`sessionStart`sessionEnd;
      updvalz:(uid;`open;.util.za2ip[.z.a];.z.P;0Np);
      .util.ammend[`dailyConns;(.z.w;updkols);updvalz];
      updUserNumUsers[] ];
    .web.authFails[.z.w]:fails+1];
  :("authResp";ok);
 }

