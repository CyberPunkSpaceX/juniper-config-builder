"""QoS (class of service) for voice and video.

Uses the four forwarding classes every EX switch has out of the box:

* expedited-forwarding (queue 5): voice, DSCP EF (46)
* assured-forwarding (queue 1): video and call signalling, DSCP AF41/AF42/CS4 and CS3/AF31
* network-control (queue 7): routing and spanning tree, DSCP CS6/CS7
* best-effort (queue 0): everything else

A DSCP classifier on the chosen ports puts packets in those classes, and a
scheduler map shares the bandwidth on every port so voice is never starved.
"""

from __future__ import annotations

PRESETS = {
    "voice": {"title": "Voice only", "voice": "20", "video": "0"},
    "voice-video": {"title": "Voice and video", "voice": "20", "video": "30"},
    "custom": {"title": "Custom", "voice": "", "video": ""},
}

QOS_DEFAULTS = {
    "enabled": False,
    "preset": "voice-video",
    "trust": "access",          # access | all: ports whose DSCP markings are trusted
    "voice_percent": "20",
    "video_percent": "30",
    "control_percent": "5",
    "signalling_as_video": True,
}

CLASSIFIER = "VOICE-VIDEO-DSCP"
SCHED_MAP = "VOICE-VIDEO-MAP"


def _pct(ctx, label, v, default, field=None):
    v = str(v if v not in (None, "") else default).strip().rstrip("%")
    if not v.isdigit() or not 0 <= int(v) <= 100:
        ctx.error("QoS", f"{label} must be a percentage (0-100).", field)
        return int(default)
    return int(v)


def apply(ctx) -> None:
    q = {**QOS_DEFAULTS, **(ctx.p.get("qos") or {})}
    if not q.get("enabled") or q.get("enabled") in ("false", "0"):
        return
    preset = PRESETS.get(q.get("preset")) or PRESETS["voice-video"]
    voice = _pct(ctx, "Voice bandwidth", preset["voice"] or q.get("voice_percent"), 20)
    video = _pct(ctx, "Video bandwidth", preset["video"] or q.get("video_percent"), 30)
    if preset is PRESETS["custom"]:
        voice = _pct(ctx, "Voice bandwidth", q.get("voice_percent"), 20, "qos.voice_percent")
        video = _pct(ctx, "Video bandwidth", q.get("video_percent"), 30, "qos.video_percent")
    control = _pct(ctx, "Network control bandwidth", q.get("control_percent"), 5, "qos.control_percent")
    best = 100 - voice - video - control
    if best < 10:
        ctx.error("QoS", f"Voice, video and network control add up to {100 - best}%; leave at least 10% for everything else.")
        return
    if voice > 40:
        ctx.warn("QoS", "More than 40% for voice is unusual: voice is a strict-priority queue and can starve other traffic.")

    ports = ctx.res.ports
    access = sorted(n for n, u in ports.items() if u.get("use") == "access")
    trunks = sorted(n for n, u in ports.items() if u.get("use") == "trunk")
    lags = [r["name"] for r in ctx.p.get("lags") or [] if r.get("name") and r.get("mode") in ("trunk", "access")]
    trusted = access + (trunks + lags if q.get("trust") == "all" else [])
    shaped = access + trunks + lags
    if not shaped:
        ctx.warn("QoS", "QoS is on, but there are no access, trunk or LAG ports to apply it to.")
        return

    cfg = ctx.cfg
    cfg.comment("QoS: voice in expedited-forwarding (EF), video in assured-forwarding (AF41)")
    cls = ("class-of-service", "classifiers", f"dscp {CLASSIFIER}")
    cfg.add(cls, "import default")
    cfg.add(cls + ("forwarding-class expedited-forwarding", "loss-priority low"), "code-points ef")
    video_points = ["af41", "af42", "cs4"]
    if q.get("signalling_as_video", True) not in (False, "false", "0"):
        video_points += ["cs3", "af31"]
    if video:
        for cp in video_points:
            cfg.add(cls + ("forwarding-class assured-forwarding", "loss-priority low"), f"code-points {cp}")
    cfg.add(cls + ("forwarding-class network-control", "loss-priority low"), "code-points cs6")
    cfg.add(cls + ("forwarding-class network-control", "loss-priority low"), "code-points cs7")

    sch = ("class-of-service", "schedulers")
    cfg.add(sch + ("VOICE",), "priority strict-high")
    cfg.add(sch + ("VOICE",), f"transmit-rate percent {voice}")
    cfg.add(sch + ("VIDEO",), f"transmit-rate percent {max(video, 1)}")
    cfg.add(sch + ("NETWORK-CONTROL",), f"transmit-rate percent {control}")
    cfg.add(sch + ("BEST-EFFORT",), "transmit-rate remainder")
    smap = ("class-of-service", "scheduler-maps", SCHED_MAP)
    for fc, s in (("expedited-forwarding", "VOICE"), ("assured-forwarding", "VIDEO"),
                  ("network-control", "NETWORK-CONTROL"), ("best-effort", "BEST-EFFORT")):
        cfg.add(smap + (f"forwarding-class {fc}",), f"scheduler {s}")

    for port in shaped:
        cfg.add(("class-of-service", "interfaces", port), f"scheduler-map {SCHED_MAP}")
    for port in trusted:
        cfg.add(("class-of-service", "interfaces", port, "unit 0", "classifiers"), f"dscp {CLASSIFIER}")
    if q.get("trust") != "all" and (trunks or lags):
        ctx.warn("QoS", "Uplinks (trunks and LAGs) share bandwidth by class but do not trust DSCP. Choose "
                        "'all ports' if the device at the other end marks traffic correctly (a core switch usually does).")
    if not ctx.p["services"].get("lldp_med"):
        ctx.warn("QoS", "Turn on LLDP-MED (Services tab) so IP phones learn the voice VLAN by themselves.")
    if not any(r.get("voice") for r in ctx.p.get("ports") or [] if r.get("mode") == "access"):
        ctx.warn("QoS", "No access port has a voice VLAN. Set one on the Ports tab so phones get their own VLAN.")
    ctx.warn("QoS", "QoS options differ by model and Junos release. Run 'commit check' before you commit.")
