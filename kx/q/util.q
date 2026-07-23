.util.za2ip:{enlist"."sv string"h"$0x0 vs x}
//Behold the below update func
.util.ammend:.[;;:;]
//TODO ==> move below to different script?
.config.MONTH_MAP:("0"^-2$string[(1+til 12)])!string(`January`February`March`April`May`June`July`August`September`October`November`December)
.util.prettyDate:{"-"sv'reverse each .["."vs'string[x];;{MONTH_MAP[x]}](til count x;1)}
.util.prettyTime:{$[any w:x=00:00 12:00;@[string[x];0 1;:;"12"],("am";"pm")first where w;$[x<12:00;string[x],"am";string[x-12:00],"pm"]]}

// Persist a named table to the kdb database directory
.util.persist:{[t] .Q.dd[hsym `$.config.ENV`BLACKBOX_DB_DIR;t] set get t;}

// Random 32-char hex salt
.util.newSalt:{raze string md5 string first neg[1]?0Ng}

// Stretched, salted password hash.
// ~100ms per attempt; swap for a real KDF if this ever guards more than a personal vault.
.util.hashPass:{[salt;pass] r:pass; do[100000; r:raze string md5 salt,r]; r}

// Bitwise XOR of two equal-length byte vectors (q has no native byte-XOR - decompose to
// bits, use <> as XOR on booleans, reassemble). Used by hmacMd5 below.
.util.xorBytes:{[x;y] "x"$2 sv/: (0b vs/: x) <> 0b vs/: y}

// HMAC-MD5 (RFC 2104 construction over the native md5). Used for the login challenge-
// response (see authUser/getAuthChallenge in blackbox.q) so the password itself never has
// to cross the wire - only a proof that the client can compute the same stored hash the
// server already has. q has no SHA-256/bignum, which is what real SRP would need; this is
// the deliberately lighter-weight alternative the design explicitly allows for.
// Verified byte-for-byte against Node's crypto.createHmac('md5', ...) across empty-key,
// short-key and >blocksize-key cases before this went anywhere near the auth path.
.util.hmacBlockSize:64
.util.hmacMd5:{[hkey;msg]
  bs:.util.hmacBlockSize;
  kb:`byte$hkey;
  kb:$[bs<count kb; `byte$md5 hkey; kb];
  kb:kb,(bs-count kb)#0x00;
  ipad:bs#0x36;
  opad:bs#0x5c;
  inner:md5 "c"$(.util.xorBytes[kb;ipad]),`byte$msg;
  md5 "c"$(.util.xorBytes[kb;opad]),inner
 }

// Actual free/used/total space (in KB) for the filesystem hosting `path`, via `df -Pk`.
// `path` is always a server-configured directory (BLACKBOX_VAULT_DIR), never client input,
// so shelling out here carries none of the injection risk that ruled out shelling out for
// the auth crypto - this is a fixed, trusted argument, not attacker-controlled data.
.util.diskStats:{[path]
  lines:system"df -Pk ",path;
  toks:" " vs lines[1];
  toks:toks where 0<count each toks;
  `totalKB`usedKB`availKB!"J"$toks 1 2 3
 }

// Write/replace a user's auth credentials (keyed on userid). Amends passphrase/salt in
// place on an existing row so any already-stored master-key-envelope columns (mek/mekIv/
// wrapSalt - see setMEK/changePassword in blackbox.q) are left untouched; only creates a
// blank-envelope row from scratch for a brand new userid.
.util.putUser:{[uid;hash;salt]
  if[not `userinfo in key `.; userinfo::([userid:0#`] passphrase:();salt:();mek:();mekIv:();wrapSalt:();isAdmin:0#0b)];
  $[uid in exec userid from userinfo;
    userinfo[uid;`passphrase`salt]:(hash;salt);
    `userinfo upsert 1!enlist `userid`passphrase`salt`mek`mekIv`wrapSalt`isAdmin!(uid;hash;salt;"";"";"";0b)];
  .util.persist[`userinfo];
 }
