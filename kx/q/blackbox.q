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
    salt:();
    fileKeyWrapped:();
    fileKeyIv:();
    docId:0#`g;
    version:0#0Nj;
    latest:0#0b;
    thumbnail:();
    thumbnailIv:());
  ];
// Ensure uploads carries master-key-envelope columns (legacy rows load without them -
// they keep decrypting via the old per-file salt path, see deriveKeyForSalt client-side)
if[`uploads in key `.;
  if[not `fileKeyWrapped in cols uploads;
    uploads:1!update fileKeyWrapped:(count i)#enlist"",fileKeyIv:(count i)#enlist"" from 0!uploads];
  // Ensure uploads carries versioning columns - every pre-existing row becomes version 1
  // (and the only, therefore latest, version) of its own document.
  if[not `docId in cols uploads;
    uploads:1!update docId:fileid, version:(count i)#1, latest:(count i)#1b from 0!uploads];
  // Ensure uploads carries thumbnail columns (legacy rows just show their file-type icon)
  if[not `thumbnail in cols uploads;
    uploads:1!update thumbnail:(count i)#enlist"",thumbnailIv:(count i)#enlist"" from 0!uploads]];

// Ensure userinfo carries a per-user salt column (legacy rows load without one)
if[`userinfo in key `.;
  if[not `salt in cols userinfo; userinfo:1!update salt:(count i)#enlist"" from 0!userinfo];
  // Ensure userinfo carries master-key-envelope columns (added for key-wrapping support)
  if[not `mek in cols userinfo;
    userinfo:1!update mek:(count i)#enlist"",mekIv:(count i)#enlist"",wrapSalt:(count i)#enlist"" from 0!userinfo];
  // Ensure userinfo carries an admin flag (nobody is admin by default - bootstrap the first
  // one from the console with setAdmin, see below)
  if[not `isAdmin in cols userinfo;
    userinfo:1!update isAdmin:(count i)#0b from 0!userinfo]];

//===================================LOGIC====================================//
broadCast:{neg[x]@\:y;}

recentUploadsForUser:{[params]
  / Only ever return the authenticated caller's own metadata. One row per document - only
  / its latest version - older revisions are reachable via getFileVersions. fileKeyWrapped/
  / fileKeyIv/salt are included so the client can decrypt a thumbnail directly from this
  / list without a separate getDownloadToken round trip per file - it's not a new exposure,
  / the owner could already fetch the same wrapped key per-file via a download token anyway.
  uid:.web.currentUser[];
  res:select string fileid, fileName, mimeType, category, tags, uploadDate, fileSize,
    string docId, version, fileKeyWrapped, fileKeyIv, salt, thumbnail, thumbnailIv
    from uploads where userid=uid, latest;
  :("recentUploads";res);
 }

/ Every revision of one logical document, newest first. Used to populate a file's version
/ history panel - download/preview of any listed fileid reuses the existing per-file flow.
getFileVersions:{[params]
  uid:.web.currentUser[];
  did:`$params`docId;
  res:`version xdesc select string fileid, fileName, uploadDate, fileSize, version, latest
    from uploads where userid=uid, docId=did;
  :("fileVersions";res);
 }

deviceInfo:{
  .mk.d:x;
  show x;
 }

/ Begin a chunked upload: validate the declared size, check there's actually room for it on
/ the host disk, and stash metadata until every chunk has landed via uploadChunk/finishUpload.
startUpload:{[params]
  uid:.web.currentUser[];
  fileSize:"j"$params`fileSize;
  if[.config.MAXUPLOAD < fileSize; :("Error";"File exceeds the maximum allowed size")];

  / Reject up front if the disk is already too full, or if this file alone would push it
  / past the threshold - both checked before a single byte is written, rather than
  / discovering it mid-write with a truncated, unrecoverable file already on disk.
  ds:.util.diskStats[.config.ENV[`BLACKBOX_VAULT_DIR]];
  if[(100*ds[`availKB]%ds[`totalKB]) < .config.MIN_DISK_HEADROOM_PCT;
    :("Error";"Server disk is nearly full - uploads are paused until space is freed")];
  if[(100*(ds[`availKB]-fileSize%1024)%ds[`totalKB]) < .config.MIN_DISK_HEADROOM_PCT;
    :("Error";"Not enough disk headroom left for a file this size")];

  / An empty docId means a brand new document (this upload becomes its own v1); a non-empty
  / one means "new version of an existing document" - which must already belong to this
  / user, or anyone could attach revisions to (and hide the latest version of) someone
  / else's file just by guessing/replaying a docId.
  isNewVersion:0<count params`docId;
  if[isNewVersion;
    did:`$params`docId;
    if[not uid in exec userid from uploads where docId=did;
      :("Error";"Not authorised to version this file")]];

  fid:`$string first neg[1]?0Ng;
  .web.uploadSessions[fid]:`userid`fileName`mimeType`category`tags`iv`salt`fileKeyWrapped`fileKeyIv`docId`thumbnail`thumbnailIv`bytesWritten!(
    uid;params`fileName;params`mimeType;`$params`category;params`tags;params`iv;params`salt;
    params`fileKeyWrapped;params`fileKeyIv;$[isNewVersion;did;fid];params`thumbnail;params`thumbnailIv;0);
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

  did:sess`docId;
  priorVersions:exec version from uploads where docId=did;
  ver:1+max 0,priorVersions;
  / Demote whatever was latest for this document before inserting the new current version -
  / if this upload never reaches here, the old version simply stays latest.
  if[0<count priorVersions; update latest:0b from `uploads where docId=did, latest];

  `uploads upsert 1!enlist `fileid`userid`fileName`mimeType`category`tags`uploadDate`fileSize`iv`salt`fileKeyWrapped`fileKeyIv`docId`version`latest`thumbnail`thumbnailIv!(
    fid;uid;sess`fileName;sess`mimeType;sess`category;sess`tags;.z.P;sess`bytesWritten;sess`iv;sess`salt;
    sess`fileKeyWrapped;sess`fileKeyIv;did;ver;1b;sess`thumbnail;sess`thumbnailIv);
  .util.persist[`uploads];
  .web.uploadSessions:.web.uploadSessions _ fid;
  .util.logm"Chunked upload finished for ",string[uid]," -> ",string fid;
  notifyFileListChanged[uid];
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
  :("downloadToken";`fileid`token`fileName`mimeType`iv`salt`fileKeyWrapped`fileKeyIv!(
    string fid;
    string tok;
    rec`fileName;
    rec`mimeType;
    rec`iv;
    rec`salt;
    rec`fileKeyWrapped;
    rec`fileKeyIv
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

  / If this was the current revision, promote the next-newest remaining one so the document
  / doesn't just vanish from the list while older versions still exist.
  if[rec`latest;
    remaining:0!select from uploads where docId=rec`docId;
    if[0<count remaining;
      newest:first `version xdesc remaining;
      update latest:1b from `uploads where fileid=newest`fileid]];

  .util.persist[`uploads];
  .util.logm"Deleted file ",string[fid]," for ",string uid;
  notifyFileListChanged[uid];
  :("deleteSuccess";string fid);
 }

getSystemStats:{[params]
  uid:.web.currentUser[];
  totalSize:0^exec sum fileSize from uploads where userid=uid;
  / Capacity isn't a fixed quota - it's "what you've used plus whatever's actually free on
  / the host disk right now", so it honestly shrinks/grows as anything else on that disk
  / (OS, other apps, other users) uses or frees space, instead of showing a fake ceiling.
  ds:.util.diskStats[.config.ENV[`BLACKBOX_VAULT_DIR]];
  capacity:totalSize+1024*ds[`availKB];
  :("systemStats";`used`capacity!(totalSize;capacity));
 }

updUserNumUsers:{
  active:exec i from dailyConns where not null userid,event=`open,not null sessionStart,null sessionEnd;
  numusers:count active;
  msg:-8!.j.j(`numUsers;(enlist`numusers)!enlist numusers),enlist string[.z.T];
  .util.logm"Broadcasting message to ",string[numusers]," connected users";
  broadCast[(exec handle from dailyConns)active;msg];
 }

/ Push a lightweight refresh signal to every active session (tab/device) for this user, so
/ an upload or delete made from one device shows up on others without a manual reload. The
/ receiving client just re-fetches its own file list/stats - no diff is sent, so this can't
/ leak anything a plain recentUploadsForUser call wouldn't already.
notifyFileListChanged:{[uid]
  / Exclude the calling handle - it already refreshes itself via the direct
  / uploadSuccess/deleteSuccess response, so this is only for the user's OTHER tabs/devices.
  handles:(exec handle from dailyConns where uid=userid,event=`open,not null sessionStart,null sessionEnd) except .z.w;
  if[0=count handles; :(::)];
  msg:-8!.j.j(`fileListUpdated;1b),enlist string[.z.T];
  broadCast[handles;msg];
 }

/addUser `userid`passphrase!("myUser";"myPassword")
addUser:{
  uid:`$x`userid;
  salt:.util.newSalt[];
  .util.logm"Adding new user: ",string uid;
  .util.putUser[uid;.util.hashPass[salt;x`passphrase];salt];
 }

/setAdmin[`myUser;1b]  -- grant admin rights (or 0b to revoke). Console-only, deliberately -
/granting the ability to create/delete other accounts over the network is a bigger decision
/than anything else exposed to the web UI, so it stays a physical/SSH-access action, same as
/account creation itself always has been. Bootstrap your first admin with this after addUser.
setAdmin:{[uid;flag]
  known:(`userinfo in key `.) and uid in exec userid from userinfo;
  if[not known; '"unknown user"];
  userinfo[uid;`isAdmin]:flag;
  .util.persist[`userinfo];
  .util.logm"Admin flag for ",string[uid]," set to ",string flag;
 }

/ Shared guard for the admin-only functions below - .web.allowed only checks "is this
/ function reachable at all", not "is THIS caller allowed to call it".
requireAdmin:{[uid] (`userinfo in key `.) and uid in exec userid from userinfo where isAdmin}

/ Admin-only: list every account with basic stats, for the user-management panel.
adminListUsers:{[params]
  uid:.web.currentUser[];
  if[not requireAdmin[uid]; :("Error";"Not authorised")];
  base:`userid xkey select userid, isAdmin from userinfo;
  perUser:select numFiles:count i, totalSize:sum fileSize by userid from uploads where latest;
  joined:0!base lj perUser;
  joined:update numFiles:0^numFiles, totalSize:0^totalSize from joined;
  :("adminUsersList";select string userid, isAdmin, numFiles, totalSize from joined);
 }

/ Admin-only: create a new account. The initial password never crosses the wire even here -
/ the admin's browser computes the salted auth hash locally (same derivation changePassword
/ already uses) and sends only that; the new user's MEK bootstraps itself on their own first
/ login exactly like a console-created account does.
adminCreateUser:{[params]
  uid:.web.currentUser[];
  if[not requireAdmin[uid]; :("Error";"Not authorised")];
  newUid:`$params`userid;
  if[0=count string newUid; :("Error";"Username is required")];
  if[(`userinfo in key `.) and newUid in exec userid from userinfo;
    :("Error";"That username already exists")];
  .util.putUser[newUid;params`newHash;params`newSalt];
  .util.logm"Admin ",string[uid]," created user ",string newUid;
  :("adminUserCreated";string newUid);
 }

/ Admin-only: permanently delete an account and every file it owns - no one could ever
/ decrypt those files again without the account anyway, so leaving them behind would just be
/ orphaned, unrecoverable ciphertext taking up space.
adminDeleteUser:{[params]
  uid:.web.currentUser[];
  if[not requireAdmin[uid]; :("Error";"Not authorised")];
  targetUid:`$params`userid;
  if[targetUid~uid; :("Error";"Cannot delete your own account")];
  if[not targetUid in exec userid from userinfo; :("Error";"User not found")];

  theirFiles:exec fileid from uploads where userid=targetUid;
  {[fid]
    fpth:.config.ENV[`BLACKBOX_VAULT_DIR],"/",string fid;
    .[hdel;enlist hsym `$fpth;{[p;e] .util.logm"Vault file already absent: ",p}[fpth]];
   } each theirFiles;
  `uploads set 1!delete from 0!uploads where userid=targetUid;
  `userinfo set 1!delete from 0!userinfo where userid=targetUid;
  .util.persist[`uploads];
  .util.persist[`userinfo];
  .util.logm"Admin ",string[uid]," deleted user ",string[targetUid]," (",string[count theirFiles]," files removed)";
  :("adminUserDeleted";string targetUid);
 }

/ Issue a single-use login challenge. The salt is whatever's actually stored for this user
/ (empty means their account predates salted hashing - see the legacy branch in authUser),
/ or a fake-but-plausible one for an unknown userid so the response shape doesn't itself
/ reveal which usernames exist. Opportunistically prunes expired challenges on every call
/ rather than running a separate timer for it.
getAuthChallenge:{[params]
  live:.z.P<=(value .web.authChallenges)[;2];
  .web.authChallenges:((key .web.authChallenges) where live)!(value .web.authChallenges) where live;

  uid:`$params`userid;
  exists:(`userinfo in key `.) and uid in exec userid from userinfo;
  salt:$[exists; (userinfo uid)`salt; .util.newSalt[]];
  nonce:`$.util.newSalt[],.util.newSalt[];
  .web.authChallenges[nonce]:(uid;.z.w;.z.P+0D00:02:00);
  :("authChallenge";`nonce`salt!(string nonce;salt));
 }

/ Verify a login proof against a previously-issued challenge, without the password itself
/ ever having been sent. The client computes AK the same way the stored `passphrase` hash
/ was derived (salted .util.hashPass, or plain md5 for a legacy pre-salt account) and proves
/ it knows AK via HMAC-MD5(AK, nonce) - see .util.hmacMd5 in util.q for why MD5/HMAC rather
/ than real SRP (q has no SHA-256 or bignum to build that on safely).
authUser:{[creds]
  .util.logm"Requesting authentication for handle: ",string[.z.w];
  noAuth:{("authResp";`ok`mek`mekIv`wrapSalt`isAdmin!(0b;"";"";"";0b))};
  if[any all@/:null creds; :noAuth[]];
  if[not `userinfo in key `.; :noAuth[]];

  / Rate limit brute-force attempts per handle
  fails:$[.z.w in key .web.authFails; .web.authFails .z.w; 0];
  if[fails>=.config.MAXFAILS; .util.logm"Auth attempts exceeded on handle ",string[.z.w]; :noAuth[]];

  nonce:`$creds`nonce;
  if[not nonce in key .web.authChallenges; .web.authFails[.z.w]:fails+1; :noAuth[]];
  chal:.web.authChallenges nonce;
  .web.authChallenges:.web.authChallenges _ nonce; / single-use regardless of outcome

  uid:`$creds`userid;
  ok:0b; rec:(::);
  if[(chal[0]~uid) and (chal[1]=.z.w) and .z.P<=chal 2;
    exists:uid in exec userid from userinfo;
    if[exists;
      rec:userinfo uid;
      ok:(raze string .util.hmacMd5[rec`passphrase;string nonce])~creds`proof]];

  if[not ok; .web.authFails[.z.w]:fails+1; :noAuth[]];

  .web.sessions[.z.w]:uid;
  .web.authFails:.web.authFails _ .z.w;
  updkols:`userid`event`ip`sessionStart`sessionEnd;
  updvalz:(uid;`open;.util.za2ip[.z.a];.z.P;0Np);
  .util.ammend[`dailyConns;(.z.w;updkols);updvalz];
  updUserNumUsers[];
  / mek/mekIv/wrapSalt are blank for a user who has never logged in from a browser yet
  / (created via console addUser) or who predates the master-key-envelope scheme - the
  / client bootstraps a fresh one in that case (see handleAuth/setMEK).
  :("authResp";`ok`mek`mekIv`wrapSalt`isAdmin!(1b;rec`mek;rec`mekIv;rec`wrapSalt;rec`isAdmin));
 }

/ Client-driven upgrade of a legacy (pre-salt, single-round-md5) auth hash to the salted
/ scheme, run once automatically right after a successful legacy-scheme login. authUser can
/ no longer do this transparently server-side the way it used to - the server never sees the
/ plaintext password anymore - so the browser (which just proved it knows the password)
/ derives the new salted hash itself and pushes it here.
upgradeLegacyAuth:{[params]
  uid:.web.currentUser[];
  userinfo[uid;`passphrase`salt]:(params`newHash;params`newSalt);
  .util.persist[`userinfo];
  .util.logm"Upgraded legacy password hash for ",string uid;
  :("legacyAuthUpgraded";1b);
 }

/ Store the caller's newly generated, password-wrapped master encryption key. The server
/ only ever sees ciphertext. Called once after first login (no MEK yet) or to bootstrap a
/ replacement after an admin-driven password reset invalidates the previous one (see
/ changePassword for the self-service path that instead re-wraps the SAME key).
setMEK:{[params]
  uid:.web.currentUser[];
  userinfo[uid;`mek`mekIv`wrapSalt]:(params`mek;params`mekIv;params`wrapSalt);
  .util.persist[`userinfo];
  .util.logm"Master key envelope set for ",string uid;
  :("mekSet";1b);
 }

/ Self-service password change. The new password never crosses the wire either - the client
/ sends the already-salted-and-hashed auth verifier (same derivation authUser checks against)
/ plus the MEK, re-wrapped under the new password client-side. Only the envelope and the
/ auth hash change here; nothing on disk gets re-encrypted, so every file stays readable.
changePassword:{[params]
  uid:.web.currentUser[];
  userinfo[uid;`passphrase`salt]:(params`newHash;params`newSalt);
  userinfo[uid;`mek`mekIv`wrapSalt]:(params`newMek;params`newMekIv;params`newWrapSalt);
  .util.persist[`userinfo];
  .util.logm"Password changed for ",string uid;
  :("passwordChanged";1b);
 }

