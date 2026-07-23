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

// Write/replace a user record (keyed on userid)
.util.putUser:{[uid;hash;salt] `userinfo upsert 1!enlist `userid`passphrase`salt!(uid;hash;salt); .util.persist[`userinfo];}
