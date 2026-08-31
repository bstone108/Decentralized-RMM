# Deployment

Status: **binding** for corporate/mass distribution.

## Binaries (separately deployable)

| Binary | Function |
| --- | --- |
| `rmm-pack` | Builds platform-native identity-provisioned installer trees |
| `rmm-agent` | Platform agent: endpoint management, mesh listen, local presence advert |
| `rmm-console` | Native GUI operator console / authenticated mesh peer; **no agent function** |
| `rmm` | Host-info helper only (not a dual-role process) |

Dual-role `rmm --role dual` is withdrawn.

## Packager

```bash
rmm-pack build \
  --issuer-data ~/.rmm-console \
  --agent dist/rmm-agent \
  --org acme \
  --cidr 10.0.0.0/8 \
  --bootstrap rmm1:issuer=10.0.0.9:7946 \
  --os linux --arch amd64 \
  --desktop authorization-required \
  --uses exactly-one \
  --self-update
```

Optional `--console` copies a separately deployable console binary into the
same tree; it is never required to manage endpoints.

Trees:

| OS | Native pieces |
| --- | --- |
| Linux | `rmm-agent`, `install.sh`, `rmm-agent.service`, enrollment + `POLICY.txt` |
| macOS | `rmm-agent`, `install.sh`, `io.rmm.agent.plist`, enrollment + `POLICY.txt` |
| Windows | `rmm-agent.exe`, `install.ps1`, enrollment + `POLICY.txt` |

`rmm-pack verify --dir TREE` is the independent artifact+manifest check.

The issuer private key stays in `--issuer-data`. `ScanForbidden` refuses to
emit a tree that contains the seed, a password field, or an unrestricted CIDR.

## Agent install

Install scripts print `POLICY.txt`, copy the enrollment bundle into the data
directory, and start the OS-native service. `rmm-agent listen` consumes
enrollment if present, writes `POLICY.txt` for audit, then listens and
advertises same-host mesh presence for a co-located console.
