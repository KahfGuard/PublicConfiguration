# =====================================================================
#  Distribution Router -- DNS forwarder HEALTH CHECK (retrofit module)
#  VERSION 1.0  (companion of forwarder-router-dns-v2.rsc v2.2)
# =====================================================================
#  Adds failover to an ALREADY RUNNING DNS interception. It changes nothing else:
#  no address-list, VPN/TOR, DoT/DoQ/DoH or IPv6 rule is touched. The only
#  existing rules it ever changes are the two static Do53 dst-nat rules named
#  in kahfHcDisableOld, and only when switched to "live" mode.
#
#  Rollout:  1) import in dry mode, watch `/log print where message~"kahf-hc"`
#            2) /system script set kahf-hc-mode source=test   (rules built disabled; inspect)
#            3) /system script set kahf-hc-mode source=live, with
#               kahfHcFailsafeMin=10 on the import for the first live run
#  Usage: /import file=forwarder-router-dns-healthcheck.rsc
# =====================================================================

# ===== CHANGE THESE PER ISP =====
# forwarders, comma separated (1 or more)
:global kahfHcFwds      "114.31.10.68,114.31.10.69"
# used only while ALL forwarders are down, in this order
:global kahfHcFallbacks "203.190.10.120,1.1.1.3,1.0.0.3,8.8.8.8"
# dst-address-list the existing intercept rules match
:global kahfHcDst       "!Bypass_Safe"
# yes: also redirect queries addressed to a dead forwarder
:global kahfHcRescue    "yes"
# uplink interface (fallback queries are masqueraded out of it)
:global kahfHcOutIf     "ether2"
# comment of the first existing static Do53 rule
:global kahfHcPlaceBefore "Do53 UDP"
# comment regex of the static rules replaced in live mode
:global kahfHcDisableOld  "Do53 (UDP|TCP)"
# dry | test | live
:global kahfHcMode      "dry"
# name resolved by every probe
:global kahfHcProbeName "google.com"
# probe + controller period
:global kahfHcInterval 3s
# consecutive failed probes before a target is marked down
:global kahfHcDownN 3
# consecutive good probes before it is marked up again
:global kahfHcUpN 3
# >0: auto-run kahf-hc-uninstall after N minutes (use during first live test, then remove scheduler kahf-hc-failsafe)
:global kahfHcFailsafeMin 0

# ====================================================================
#  HEALTH CHECK LAYER (v2.2) -- forwarder failover for DNS interception
# ====================================================================
#  Probes every forwarder (and every fallback) with a real DNS query via
#  /tool netwatch, then a controller script (scheduler "kahf-hc", every
#  $kahfHcInterval) rebuilds the port-53 dst-nat rules for whatever is alive:
#    - both forwarders up      -> round-robin (nth) across them
#    - one forwarder down      -> everything to the survivor
#    - all forwarders down     -> first healthy fallback (needs srcnat
#                                 masquerade so the reply returns here)
#  Debounce: kahfHcDownN consecutive bad probes to fail, kahfHcUpN good to recover.
#
#  MODES  (/system script set kahf-hc-mode source=<mode>):
#    dry   probes + logs only, NAT untouched          (safe first install)
#    test  builds the rules DISABLED so you can inspect them
#    live  builds the rules enabled and disables kahfHcDisableOld
#  Inspect:   /tool netwatch print ; /log print where message~"kahf-hc"
#             /ip firewall nat print where comment~"KAHF-HC"
#  Roll back: /system script run kahf-hc-uninstall
#  Change settings: set mode dry first, then re-import this file.
# ====================================================================

# --- reset controller state, remove any previous install -------------
:global kahfHcCnt [:toarray ""]
:global kahfHcState ""
:global kahfHcAlive ""
/system scheduler remove [find where comment="KAHF-HC"]
:if ([:len $kahfHcDisableOld] > 0) do={ /ip firewall nat enable [find where comment~$kahfHcDisableOld] }
/ip firewall nat remove [find where comment~"^KAHF-HC:"]
/tool netwatch remove [find where comment="KAHF-HC"]
/ip firewall address-list remove [find where comment="KAHF-HC"]
/system script remove [find where name~"^kahf-hc-"]

# --- scripts ----------------------------------------------------------
/system script add name=kahf-hc-mode source=$kahfHcMode comment="KAHF-HC: dry | test | live"
/system script add name=kahf-hc-config comment="KAHF-HC" source=(":global kahfHcFwds \"" . $kahfHcFwds . "\"\n:global kahfHcFallbacks \"" . $kahfHcFallbacks . "\"\n:global kahfHcDst \"" . $kahfHcDst . "\"\n:global kahfHcRescue \"" . $kahfHcRescue . "\"\n:global kahfHcDisableOld \"" . $kahfHcDisableOld . "\"\n:global kahfHcDownN " . $kahfHcDownN . "\n:global kahfHcUpN " . $kahfHcUpN . "\n")
/system script add name=kahf-hc-run comment="KAHF-HC" source="# kahf-hc-run: DNS forwarder health controller (runs every kahfHcInterval from scheduler \"kahf-hc\")\n/system script run kahf-hc-config\n:global kahfHcFwds\n:global kahfHcFallbacks\n:global kahfHcDst\n:global kahfHcRescue\n:global kahfHcDisableOld\n:global kahfHcDownN\n:global kahfHcUpN\n:global kahfHcCnt\n:global kahfHcState\n:global kahfHcAlive\n:local mode [/system script get kahf-hc-mode source]\n:if ([:typeof \$kahfHcCnt] != \"array\") do={ :set kahfHcCnt [:toarray \"\"] }\n:local cnt \$kahfHcCnt\n:if ([:typeof \$kahfHcState] != \"str\") do={ :set kahfHcState \"\" }\n:if ([:typeof \$kahfHcAlive] != \"str\") do={ :set kahfHcAlive \"\" }\n:local fwds [:toarray \$kahfHcFwds]\n:local fbs [:toarray \$kahfHcFallbacks]\n# 1. read netwatch status of every forwarder and fallback; hysteresis: DownN bad ticks to fail, UpN good ticks to recover\n:foreach ip in=[:toarray (\$kahfHcFwds . \",\" . \$kahfHcFallbacks)] do={\n  :local nwname (\"kahf-hc-\" . \$ip)\n  :local nwid [/tool netwatch find where name=\$nwname]\n  :if ([:len \$nwid] > 0) do={\n    :local st [/tool netwatch get \$nwid status]\n"
/system script set kahf-hc-run source=([/system script get kahf-hc-run source] . "    :local ak (\"alive-\" . \$ip)\n    :local bk (\"bad-\" . \$ip)\n    :local gk (\"good-\" . \$ip)\n    :local alive (\$cnt->\$ak)\n    :local bad (\$cnt->\$bk)\n    :local good (\$cnt->\$gk)\n    :if ((\$alive != true) && (\$alive != false)) do={ :set alive true }\n    :if ([:typeof \$bad] != \"num\") do={ :set bad 0 }\n    :if ([:typeof \$good] != \"num\") do={ :set good 0 }\n    :if (\$st = \"up\") do={\n      :set good (\$good + 1)\n      :set bad 0\n      :if (\$good > 1000) do={ :set good 1000 }\n      :if ((\$alive = false) && (\$good >= \$kahfHcUpN)) do={ :set alive true; :log warning (\"kahf-hc: \" . \$ip . \" UP\") }\n    }\n    :if (\$st = \"down\") do={\n      :set bad (\$bad + 1)\n      :set good 0\n      :if (\$bad > 1000) do={ :set bad 1000 }\n      :if ((\$alive = true) && (\$bad >= \$kahfHcDownN)) do={ :set alive false; :log warning (\"kahf-hc: \" . \$ip . \" DOWN\") }\n    }\n    :set (\$cnt->\$ak) \$alive\n    :set (\$cnt->\$bk) \$bad\n    :set (\$cnt->\$gk) \$good\n  }\n")
/system script set kahf-hc-run source=([/system script get kahf-hc-run source] . "}\n# persist debounce counters (global arrays cannot be written from inside nested blocks)\n:set kahfHcCnt \$cnt\n# 2. desired state: alive forwarders in config order, else the first alive fallback\n:local aliveStr \"\"\n:foreach ip in=\$fwds do={\n  :if ((\$cnt->(\"alive-\" . \$ip)) != false) do={\n    :if (\$aliveStr = \"\") do={ :set aliveStr \$ip } else={ :set aliveStr (\$aliveStr . \",\" . \$ip) }\n  }\n}\n:local fb \"\"\n:foreach ip in=\$fbs do={\n  :if ((\$fb = \"\") && ((\$cnt->(\"alive-\" . \$ip)) != false)) do={ :set fb \$ip }\n}\n:if (\$fb = \"\") do={ :set fb [:pick \$fbs 0] }\n:local sig \$aliveStr\n:if (\$aliveStr = \"\") do={ :set sig (\"FB:\" . \$fb) }\n# 3. apply only on change\n:if (\$sig != \$kahfHcState) do={\n  :log warning (\"kahf-hc: mode=\" . \$mode . \" state '\" . \$kahfHcState . \"' -> '\" . \$sig . \"'\")\n  :if (\$mode != \"dry\") do={\n    :local anchor [/ip firewall nat find where comment=\"KAHF-HC:anchor\"]\n    :if ([:len \$anchor] = 0) do={\n      :log error \"kahf-hc: anchor rule missing, NAT untouched\"\n    } else={\n")
/system script set kahf-hc-run source=([/system script get kahf-hc-run source] . "      :local old [/ip firewall nat find where comment~\"^KAHF-HC:rule\"]\n      :local dis \"no\"\n      :if (\$mode = \"test\") do={ :set dis \"yes\" }\n      :local targets \$aliveStr\n      :if (\$aliveStr = \"\") do={ :set targets \$fb }\n      :local emit do={\n        :local tt [:toarray \$csv]\n        :local n [:len \$tt]\n        :for i from=0 to=(\$n - 1) do={\n          :local c (\"/ip firewall nat add chain=dstnat action=dst-nat protocol=\" . \$pr . \" dst-port=53 \" . \$m . \" to-addresses=\" . [:pick \$tt \$i] . \" to-ports=53 disabled=\" . \$dis . \" comment=KAHF-HC:rule-\" . \$pr . \" place-before=\" . \$anchor)\n          :if (\$i < (\$n - 1)) do={ :set c (\$c . \" nth=\" . \$n . \",\" . (\$i + 1)) }\n          :local f [:parse \$c]\n          \$f\n        }\n      }\n      :foreach pr in={\"udp\";\"tcp\"} do={\n        \$emit m=(\"dst-address-list=\" . \$kahfHcDst) csv=\$targets pr=\$pr anchor=\$anchor dis=\$dis\n        :if (\$kahfHcRescue = \"yes\") do={\n          :if (\$aliveStr = \"\") do={\n            \$emit m=\"dst-address-list=Kahf_HC_Fwds\" csv=\$targets pr=\$pr anchor=\$anchor dis=\$dis\n          } else={\n            :foreach f in=\$fwds do={\n              :if ((\$cnt->(\"alive-\" . \$f)) = false) do={\n                \$emit m=(\"dst-address=\" . \$f) csv=\$targets pr=\$pr anchor=\$anchor dis=\$dis\n              }\n")
/system script set kahf-hc-run source=([/system script get kahf-hc-run source] . "            }\n          }\n        }\n      }\n      :if ([:len \$old] > 0) do={ /ip firewall nat remove \$old }\n      :if ((\$mode = \"live\") && ([:len \$kahfHcDisableOld] > 0)) do={ /ip firewall nat disable [find where comment~\$kahfHcDisableOld] }\n      # drop conntrack entries still pinned to a forwarder that just went down\n      :if (\$mode = \"live\") do={\n        :foreach f in=\$fwds do={\n          :if (((\$cnt->(\"alive-\" . \$f)) = false) && ((\",\" . \$kahfHcAlive . \",\") ~ (\",\" . \$f . \",\"))) do={\n            /ip firewall connection remove [find where reply-src-address~(\"^\" . \$f . \":53\")]\n          }\n        }\n      }\n    }\n  }\n  :set kahfHcState \$sig\n  :set kahfHcAlive \$aliveStr\n}\n")
/system script add name=kahf-hc-uninstall comment="KAHF-HC" source="# kahf-hc-uninstall: remove the health-check layer and re-enable the original static rules\n/system script run kahf-hc-config\n:global kahfHcDisableOld\n/system scheduler remove [find where comment=\"KAHF-HC\"]\n:if ([:len \$kahfHcDisableOld] > 0) do={ /ip firewall nat enable [find where comment~\$kahfHcDisableOld] }\n/ip firewall nat remove [find where comment~\"^KAHF-HC:\"]\n/tool netwatch remove [find where comment=\"KAHF-HC\"]\n/ip firewall address-list remove [find where comment=\"KAHF-HC\"]\n:log warning \"kahf-hc: uninstalled, original DNS NAT rules re-enabled\"\n"

# --- probes -------------------------------------------------------------
:foreach ip in=[:toarray ($kahfHcFwds . "," . $kahfHcFallbacks)] do={
  /tool netwatch add name=("kahf-hc-" . $ip) type=dns host=$kahfHcProbeName dns-server=$ip record-type=A interval=$kahfHcInterval timeout=1s comment="KAHF-HC"
}
:foreach ip in=[:toarray $kahfHcFwds] do={
  /ip firewall address-list add list=Kahf_HC_Fwds address=$ip comment="KAHF-HC"
}

# --- srcnat for fallback tier: customer queries only: sources in Kahf_HC_Fwds are excluded,
#     never the forwarders own upstream queries ----------------------------
:foreach ip in=[:toarray $kahfHcFallbacks] do={
  :foreach pr in={"udp";"tcp"} do={
    :if ([:len $kahfHcOutIf] > 0) do={
      /ip firewall nat add chain=srcnat action=masquerade protocol=$pr dst-port=53 dst-address=$ip src-address-list=!Kahf_HC_Fwds out-interface=$kahfHcOutIf comment="KAHF-HC:masq"
    } else={
      /ip firewall nat add chain=srcnat action=masquerade protocol=$pr dst-port=53 dst-address=$ip src-address-list=!Kahf_HC_Fwds comment="KAHF-HC:masq"
    }
  }
}

# --- anchor: controller inserts its rules directly above this marker --------
:local pb [/ip firewall nat find where comment~$kahfHcPlaceBefore]
:if (([:len $kahfHcPlaceBefore] > 0) && ([:len $pb] > 0)) do={
  /ip firewall nat add chain=dstnat action=passthrough disabled=yes place-before=[:pick $pb 0] comment="KAHF-HC:anchor"
} else={
  /ip firewall nat add chain=dstnat action=passthrough disabled=yes comment="KAHF-HC:anchor"
}

# --- scheduler + optional one-shot failsafe rollback -----------------------------
/system scheduler add name=kahf-hc interval=$kahfHcInterval start-time=00:00:00 on-event="/system script run kahf-hc-run" comment="KAHF-HC"
/system scheduler remove [find where name="kahf-hc-failsafe"]
:if ($kahfHcFailsafeMin > 0) do={
  /system scheduler add name=kahf-hc-failsafe interval=0s start-time=([/system clock get time] + [:totime ($kahfHcFailsafeMin * 60)]) on-event="/system script run kahf-hc-uninstall" comment="KAHF-HC-FAILSAFE"
}
:log warning ("kahf-hc: installed, mode=" . $kahfHcMode . ", fwds=" . $kahfHcFwds . ", fallbacks=" . $kahfHcFallbacks)
/system script run kahf-hc-run
