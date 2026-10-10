# A6000 USB mode matrix

The Sony ILCE-6000 Help Guide lists Auto, Mass Storage, MTP and PC Remote as
USB Connection choices. Auto selects Mass Storage or MTP according to the host;
Mass Storage exposes storage; MTP exposes media transfer; PC Remote is used by
Remote Camera Control for shooting and storing images on the computer. Source:
Sony ILCE-6000 Help Guide,
<https://helpguide.sony.net/gbmig/45349334/v1/es/contents/TP0000245081.html>.

| Mode | Official documented use | Descriptor evidence in this project | PTP candidate observed | Future read-only review |
|---|---|---|---|---|
| Auto | Host-dependent Mass Storage or MTP selection | None for Auto selection | UNKNOWN | Requires a separate sanitized observation |
| Mass Storage | Storage connection | PRIMARY_DESCRIPTOR: `08/06/50`, bulk IN/OUT | No | Not a PTP transport candidate |
| MTP | Media transfer connection | None | UNKNOWN | Requires a separate observation and protocol evidence |
| PC Remote | Remote Camera Control shooting/image storage | None | UNKNOWN | Requires documented interface evidence; no command is sent |

The current observation remains Mass Storage only (`054C:07C4`). This table
separates official documentation from primary descriptor evidence. It does not
claim that a menu option was selected or that any PTP/MTP exchange succeeded.
