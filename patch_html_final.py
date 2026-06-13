import base64, os, ast

print("="*55)
print("  Nitakusaka HTML Output Patcher")
print("="*55)

applied = []
warnings = []

# ── 1. Write the change report template ──
changes_data = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAiPgo8dGl0bGU+Tml0YWt1c2FrYSBDaGFuZ2UgUmVwb3J0IOKAlCB7eyB0YXJnZXQgfX08L3RpdGxlPgo8c3R5bGU+CiAgOnJvb3QgewogICAgLS1iZzojMEUxNDI4OyAtLWJnLWNhcmQ6IzE2MUUzQTsgLS1iZy1lbGV2OiMxQzI2NDc7IC0tYm9yZGVyOiMyQTM4NjY7CiAgICAtLWJvcmRlci1saXQ6IzNENEY4QTsgLS10ZXh0OiNFNEU5Rjc7IC0tdGV4dC1kaW06IzhCOTdCRTsgLS10ZXh0LWZhaW50OiM1QTY2OTk7CiAgICAtLWN5YW46IzJERTJFNjsgLS12aW9sZXQ6IzhCNUNGNjsgLS1hZGQ6IzNERjVBMDsgLS1yZW1vdmU6I0ZGNDM2NTsgLS1nb2xkOiNGRkM1NDI7CiAgICAtLWdyYWQtaGVybzpsaW5lYXItZ3JhZGllbnQoMTIwZGVnLCMyREUyRTYgMCUsIzhCNUNGNiA2MCUsI0ZGNUM3QyAxMDAlKTsKICAgIC0tZ3JhZC1jeWFuOmxpbmVhci1ncmFkaWVudCgxMzVkZWcsIzJERTJFNiwjNEY4QkZGKTsKICB9CiAgKnttYXJnaW46MDtwYWRkaW5nOjA7Ym94LXNpemluZzpib3JkZXItYm94O30KICBib2R5ewogICAgYmFja2dyb3VuZDpyYWRpYWwtZ3JhZGllbnQoMTIwMHB4IDYwMHB4IGF0IDgwJSAtMTAlLHJnYmEoMTM5LDkyLDI0NiwwLjE4KSx0cmFuc3BhcmVudCA2MCUpLAogICAgICAgICAgICAgICByYWRpYWwtZ3JhZGllbnQoOTAwcHggNTAwcHggYXQgMCUgMCUscmdiYSg0NSwyMjYsMjMwLDAuMTIpLHRyYW5zcGFyZW50IDU1JSksdmFyKC0tYmcpOwogICAgYmFja2dyb3VuZC1hdHRhY2htZW50OmZpeGVkO2NvbG9yOnZhcigtLXRleHQpOwogICAgZm9udC1mYW1pbHk6J0ludGVyJywtYXBwbGUtc3lzdGVtLEJsaW5rTWFjU3lzdGVtRm9udCwnU2Vnb2UgVUknLHNhbnMtc2VyaWY7bGluZS1oZWlnaHQ6MS42OwogIH0KICAubW9ub3tmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLCdGaXJhIENvZGUnLG1vbm9zcGFjZTt9CiAgLmhlYWRlcntwb3NpdGlvbjpyZWxhdGl2ZTtwYWRkaW5nOjUycHggNDBweCAzNnB4O2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7b3ZlcmZsb3c6aGlkZGVuO30KICAuaGVhZGVyOjpiZWZvcmV7Y29udGVudDoiIjtwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowOwogICAgYmFja2dyb3VuZDpyZXBlYXRpbmctbGluZWFyLWdyYWRpZW50KDkwZGVnLHRyYW5zcGFyZW50LHRyYW5zcGFyZW50IDM4cHgscmdiYSg2MSw3OSwxMzgsMC4wOCkgMzlweCx0cmFuc3BhcmVudCA0MHB4KSwKICAgICAgICAgICAgICAgcmVwZWF0aW5nLWxpbmVhci1ncmFkaWVudCgwZGVnLHRyYW5zcGFyZW50LHRyYW5zcGFyZW50IDM4cHgscmdiYSg2MSw3OSwxMzgsMC4wOCkgMzlweCx0cmFuc3BhcmVudCA0MHB4KTsKICAgIHBvaW50ZXItZXZlbnRzOm5vbmU7fQogIC5oZWFkZXItdGFne2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEwcHg7bWFyZ2luLWJvdHRvbToxNnB4O3Bvc2l0aW9uOnJlbGF0aXZlO30KICAucHVsc2V7d2lkdGg6OHB4O2hlaWdodDo4cHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDp2YXIoLS1nb2xkKTsKICAgIGJveC1zaGFkb3c6MCAwIDAgMCByZ2JhKDI1NSwxOTcsNjYsMC42KTthbmltYXRpb246cHVsc2UgMi40cyBpbmZpbml0ZTt9CiAgQGtleWZyYW1lcyBwdWxzZXswJXtib3gtc2hhZG93OjAgMCAwIDAgcmdiYSgyNTUsMTk3LDY2LDAuNSk7fTcwJXtib3gtc2hhZG93OjAgMCAwIDEwcHggcmdiYSgyNTUsMTk3LDY2LDApO30xMDAle2JveC1zaGFkb3c6MCAwIDAgMCByZ2JhKDI1NSwxOTcsNjYsMCk7fX0KICAuaGVhZGVyLXRhZyBzcGFue2NvbG9yOnZhcigtLWdvbGQpO2ZvbnQtc2l6ZToxMXB4O2xldHRlci1zcGFjaW5nOjMuNXB4O3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTtmb250LWZhbWlseTonSmV0QnJhaW5zIE1vbm8nLG1vbm9zcGFjZTt9CiAgLmhlYWRlciBoMXtmb250LXNpemU6NDZweDtmb250LXdlaWdodDo4MDA7bGV0dGVyLXNwYWNpbmc6LTEuNXB4O2xpbmUtaGVpZ2h0OjE7bWFyZ2luLWJvdHRvbToxMnB4OwogICAgYmFja2dyb3VuZDp2YXIoLS1ncmFkLWhlcm8pOy13ZWJraXQtYmFja2dyb3VuZC1jbGlwOnRleHQ7YmFja2dyb3VuZC1jbGlwOnRleHQ7LXdlYmtpdC10ZXh0LWZpbGwtY29sb3I6dHJhbnNwYXJlbnQ7d2lkdGg6Zml0LWNvbnRlbnQ7cG9zaXRpb246cmVsYXRpdmU7fQogIC5oZWFkZXIgLnRhcmdldHtkaXNwbGF5OmlubGluZS1ibG9jaztwb3NpdGlvbjpyZWxhdGl2ZTtmb250LXNpemU6MTZweDtjb2xvcjp2YXIoLS1jeWFuKTsKICAgIGZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO3BhZGRpbmc6NnB4IDE0cHg7bWFyZ2luLWJvdHRvbToyMHB4OwogICAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXItbGl0KTtib3JkZXItcmFkaXVzOjhweDtiYWNrZ3JvdW5kOnJnYmEoNDUsMjI2LDIzMCwwLjA2KTt9CiAgLmhlYWRlci1tZXRhe2Rpc3BsYXk6ZmxleDtnYXA6MjhweDtmbGV4LXdyYXA6d3JhcDtwb3NpdGlvbjpyZWxhdGl2ZTt9CiAgLmhlYWRlci1tZXRhIGRpdntmb250LXNpemU6MTJweDtjb2xvcjp2YXIoLS10ZXh0LWRpbSk7fQogIC5oZWFkZXItbWV0YSBzdHJvbmd7Y29sb3I6dmFyKC0tdGV4dCk7Zm9udC13ZWlnaHQ6NjAwO30KICAuY29udGFpbmVye21heC13aWR0aDoxMDAwcHg7bWFyZ2luOjAgYXV0bztwYWRkaW5nOjQ0cHggNDBweDt9CiAgLnNlY3Rpb257bWFyZ2luLWJvdHRvbTo0MHB4O30KICAuc2VjdGlvbi10aXRsZXtmb250LXNpemU6MTJweDtsZXR0ZXItc3BhY2luZzoyLjVweDt0ZXh0LXRyYW5zZm9ybTp1cHBlcmNhc2U7Y29sb3I6dmFyKC0tdGV4dC1kaW0pOwogICAgbWFyZ2luLWJvdHRvbToyMHB4O2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjE0cHg7fQogIC5zZWN0aW9uLXRpdGxlOjpiZWZvcmV7Y29udGVudDoiIjt3aWR0aDoyMnB4O2hlaWdodDoycHg7Ym9yZGVyLXJhZGl1czoycHg7YmFja2dyb3VuZDp2YXIoLS1ncmFkLWN5YW4pO30KICAuc2VjdGlvbi10aXRsZTo6YWZ0ZXJ7Y29udGVudDoiIjtmbGV4OjE7aGVpZ2h0OjFweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCg5MGRlZyx2YXIoLS1ib3JkZXIpLHRyYW5zcGFyZW50KTt9CiAgLm5vY2hhbmdle3BhZGRpbmc6NDBweDt0ZXh0LWFsaWduOmNlbnRlcjtib3JkZXItcmFkaXVzOjE0cHg7YmFja2dyb3VuZDp2YXIoLS1iZy1jYXJkKTsKICAgIGJvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtjb2xvcjp2YXIoLS10ZXh0LWRpbSk7fQogIC5ub2NoYW5nZSAuYmlne2ZvbnQtc2l6ZToxOHB4O2NvbG9yOnZhcigtLWFkZCk7bWFyZ2luLWJvdHRvbTo2cHg7Zm9udC13ZWlnaHQ6NjAwO30KICAuY2hhbmdlLWdyaWR7ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoxZnIgMWZyO2dhcDoxNnB4O30KICAuY2hhbmdlLWNvbHtib3JkZXItcmFkaXVzOjE0cHg7YmFja2dyb3VuZDp2YXIoLS1iZy1jYXJkKTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7b3ZlcmZsb3c6aGlkZGVuO30KICAuY2hhbmdlLWNvbCBoM3tmb250LXNpemU6MTNweDtwYWRkaW5nOjE0cHggMThweDtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpOwogICAgZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4O2ZvbnQtd2VpZ2h0OjYwMDt9CiAgLmNoYW5nZS1jb2wuYWRkIGgze2NvbG9yOnZhcigtLWFkZCk7YmFja2dyb3VuZDpyZ2JhKDYxLDI0NSwxNjAsMC4wNik7fQogIC5jaGFuZ2UtY29sLnJlbW92ZSBoM3tjb2xvcjp2YXIoLS1yZW1vdmUpO2JhY2tncm91bmQ6cmdiYSgyNTUsNjcsMTAxLDAuMDYpO30KICAuY2hhbmdlLWl0ZW17cGFkZGluZzoxMHB4IDE4cHg7Zm9udC1mYW1pbHk6J0pldEJyYWlucyBNb25vJyxtb25vc3BhY2U7Zm9udC1zaXplOjEzcHg7CiAgICBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEwcHg7fQogIC5jaGFuZ2UtaXRlbTpsYXN0LWNoaWxke2JvcmRlci1ib3R0b206bm9uZTt9CiAgLmNoYW5nZS1pdGVtLmFkZHtjb2xvcjp2YXIoLS10ZXh0KTt9CiAgLmNoYW5nZS1pdGVtLmFkZDo6YmVmb3Jle2NvbnRlbnQ6IisiO2NvbG9yOnZhcigtLWFkZCk7Zm9udC13ZWlnaHQ6NzAwO30KICAuY2hhbmdlLWl0ZW0ucmVtb3Zle2NvbG9yOnZhcigtLXRleHQtZGltKTt9CiAgLmNoYW5nZS1pdGVtLnJlbW92ZTo6YmVmb3Jle2NvbnRlbnQ6IuKIkiI7Y29sb3I6dmFyKC0tcmVtb3ZlKTtmb250LXdlaWdodDo3MDA7fQogIC5jaGFuZ2UtZW1wdHl7cGFkZGluZzoxOHB4O2NvbG9yOnZhcigtLXRleHQtZmFpbnQpO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtc3R5bGU6aXRhbGljO3RleHQtYWxpZ246Y2VudGVyO30KICAuZm9vdGVye2JvcmRlci10b3A6MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7cGFkZGluZzoyOHB4IDQwcHg7dGV4dC1hbGlnbjpjZW50ZXI7Y29sb3I6dmFyKC0tdGV4dC1mYWludCk7Zm9udC1zaXplOjEycHg7fQogIC5mb290ZXIgLmJyYW5ke2ZvbnQtZmFtaWx5OidKZXRCcmFpbnMgTW9ubycsbW9ub3NwYWNlO2ZvbnQtd2VpZ2h0OjcwMDsKICAgIGJhY2tncm91bmQ6dmFyKC0tZ3JhZC1oZXJvKTstd2Via2l0LWJhY2tncm91bmQtY2xpcDp0ZXh0O2JhY2tncm91bmQtY2xpcDp0ZXh0Oy13ZWJraXQtdGV4dC1maWxsLWNvbG9yOnRyYW5zcGFyZW50O30KICBAbWVkaWEobWF4LXdpZHRoOjcwMHB4KXsuY2hhbmdlLWdyaWR7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmcjt9LmhlYWRlciBoMXtmb250LXNpemU6MzRweDt9LmNvbnRhaW5lcntwYWRkaW5nOjI4cHggMjJweDt9fQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgogIDxkaXYgY2xhc3M9ImhlYWRlciI+CiAgICA8ZGl2IGNsYXNzPSJoZWFkZXItdGFnIj48ZGl2IGNsYXNzPSJwdWxzZSI+PC9kaXY+PHNwYW4+Q2hhbmdlIERldGVjdGlvbiBSZXBvcnQ8L3NwYW4+PC9kaXY+CiAgICA8aDE+Tml0YWt1c2FrYTwvaDE+CiAgICA8ZGl2IGNsYXNzPSJ0YXJnZXQgbW9ubyI+e3sgdGFyZ2V0IH19PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJoZWFkZXItbWV0YSI+CiAgICAgIDxkaXY+R2VuZXJhdGVkIDxzdHJvbmc+e3sgZ2VuZXJhdGVkIH19PC9zdHJvbmc+PC9kaXY+CiAgICAgIDxkaXY+U3RhdHVzIDxzdHJvbmc+eyUgaWYgY2hhbmdlcy5oYXNfY2hhbmdlcyAlfUNoYW5nZXMgZGV0ZWN0ZWR7JSBlbHNlICV9Tm8gY2hhbmdlc3slIGVuZGlmICV9PC9zdHJvbmc+PC9kaXY+CiAgICA8L2Rpdj4KICA8L2Rpdj4KICA8ZGl2IGNsYXNzPSJjb250YWluZXIiPgogICAgeyUgaWYgbm90IGNoYW5nZXMuaGFzX2NoYW5nZXMgJX0KICAgICAgPGRpdiBjbGFzcz0ibm9jaGFuZ2UiPgogICAgICAgIDxkaXYgY2xhc3M9ImJpZyI+Tm8gY2hhbmdlcyBkZXRlY3RlZDwvZGl2PgogICAgICAgIDxkaXY+VGhlIHRhcmdldCdzIGF0dGFjayBzdXJmYWNlIGlzIHVuY2hhbmdlZCBzaW5jZSB0aGUgbGFzdCBzbmFwc2hvdC48L2Rpdj4KICAgICAgPC9kaXY+CiAgICB7JSBlbHNlICV9CiAgICA8ZGl2IGNsYXNzPSJzZWN0aW9uIj4KICAgICAgPGRpdiBjbGFzcz0ic2VjdGlvbi10aXRsZSI+U3ViZG9tYWluIENoYW5nZXM8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0iY2hhbmdlLWdyaWQiPgogICAgICAgIDxkaXYgY2xhc3M9ImNoYW5nZS1jb2wgYWRkIj4KICAgICAgICAgIDxoMz5OZXcgU3ViZG9tYWlucyAoe3sgY2hhbmdlcy5uZXdfc3ViZG9tYWlucyB8IGxlbmd0aCB9fSk8L2gzPgogICAgICAgICAgeyUgZm9yIHMgaW4gY2hhbmdlcy5uZXdfc3ViZG9tYWlucyAlfTxkaXYgY2xhc3M9ImNoYW5nZS1pdGVtIGFkZCI+e3sgcyB9fTwvZGl2PnslIGVsc2UgJX08ZGl2IGNsYXNzPSJjaGFuZ2UtZW1wdHkiPk5vbmU8L2Rpdj57JSBlbmRmb3IgJX0KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFuZ2UtY29sIHJlbW92ZSI+CiAgICAgICAgICA8aDM+UmVtb3ZlZCBTdWJkb21haW5zICh7eyBjaGFuZ2VzLnJlbW92ZWRfc3ViZG9tYWlucyB8IGxlbmd0aCB9fSk8L2gzPgogICAgICAgICAgeyUgZm9yIHMgaW4gY2hhbmdlcy5yZW1vdmVkX3N1YmRvbWFpbnMgJX08ZGl2IGNsYXNzPSJjaGFuZ2UtaXRlbSByZW1vdmUiPnt7IHMgfX08L2Rpdj57JSBlbHNlICV9PGRpdiBjbGFzcz0iY2hhbmdlLWVtcHR5Ij5Ob25lPC9kaXY+eyUgZW5kZm9yICV9CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJzZWN0aW9uIj4KICAgICAgPGRpdiBjbGFzcz0ic2VjdGlvbi10aXRsZSI+UG9ydCBDaGFuZ2VzPC9kaXY+CiAgICAgIDxkaXYgY2xhc3M9ImNoYW5nZS1ncmlkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFuZ2UtY29sIGFkZCI+CiAgICAgICAgICA8aDM+TmV3IE9wZW4gUG9ydHMgKHt7IGNoYW5nZXMubmV3X3BvcnRzIHwgbGVuZ3RoIH19KTwvaDM+CiAgICAgICAgICB7JSBmb3IgcCBpbiBjaGFuZ2VzLm5ld19wb3J0cyAlfTxkaXYgY2xhc3M9ImNoYW5nZS1pdGVtIGFkZCI+e3sgcCB9fTwvZGl2PnslIGVsc2UgJX08ZGl2IGNsYXNzPSJjaGFuZ2UtZW1wdHkiPk5vbmU8L2Rpdj57JSBlbmRmb3IgJX0KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjaGFuZ2UtY29sIHJlbW92ZSI+CiAgICAgICAgICA8aDM+Q2xvc2VkIFBvcnRzICh7eyBjaGFuZ2VzLmNsb3NlZF9wb3J0cyB8IGxlbmd0aCB9fSk8L2gzPgogICAgICAgICAgeyUgZm9yIHAgaW4gY2hhbmdlcy5jbG9zZWRfcG9ydHMgJX08ZGl2IGNsYXNzPSJjaGFuZ2UtaXRlbSByZW1vdmUiPnt7IHAgfX08L2Rpdj57JSBlbHNlICV9PGRpdiBjbGFzcz0iY2hhbmdlLWVtcHR5Ij5Ob25lPC9kaXY+eyUgZW5kZm9yICV9CiAgICAgICAgPC9kaXY+CiAgICAgIDwvZGl2PgogICAgPC9kaXY+CiAgICB7JSBlbmRpZiAlfQogIDwvZGl2PgogIDxkaXYgY2xhc3M9ImZvb3RlciI+R2VuZXJhdGVkIGJ5IDxzcGFuIGNsYXNzPSJicmFuZCI+Tml0YWt1c2FrYTwvc3Bhbj4g4oCUIGNvbnRpbnVvdXMgYXR0YWNrIHN1cmZhY2UgbW9uaXRvcmluZzwvZGl2Pgo8L2JvZHk+CjwvaHRtbD4K"
os.makedirs("templates", exist_ok=True)
with open("templates/changes.html.j2","wb") as f:
    f.write(base64.b64decode(changes_data))
applied.append("Created templates/changes.html.j2")

# ── 2. Patch report_module.py ──
rm_path = "modules/report_module.py"
with open(rm_path, "r", encoding="utf-8") as f:
    rm = f.read()

if '"reverse":    None,' not in rm and '"vuln":       None,' in rm:
    rm = rm.replace('"vuln":       None,', '"vuln":       None,\n        "reverse":    None,')
    applied.append("Added reverse key to load dict")
elif '"reverse":    None,' in rm:
    applied.append("reverse key already in load dict (skipped)")
else:
    warnings.append("Could not find vuln load-dict line")

if '"reverse_":     "reverse",' not in rm and '"vuln_":        "vuln",' in rm:
    rm = rm.replace('"vuln_":        "vuln",', '"vuln_":        "vuln",\n        "reverse_":     "reverse",')
    applied.append("Added reverse prefix mapping")
elif '"reverse_":     "reverse",' in rm:
    applied.append("reverse prefix already mapped (skipped)")
else:
    warnings.append("Could not find vuln prefix mapping")

if '"reverse_hosts"' not in rm and '"technologies":  set(),' in rm:
    rm = rm.replace('"technologies":  set(),', '"technologies":  set(),\n        "reverse_hosts": [],')
    applied.append("Added reverse_hosts to report dict")
elif '"reverse_hosts"' in rm:
    applied.append("reverse_hosts already present (skipped)")
else:
    warnings.append("Could not find technologies line")

if 'data.get("reverse")' not in rm and '# Summary stats' in rm:
    block = '''    # Collect reverse DNS hosts
    if data.get("reverse"):
        for host in data["reverse"].get("hostnames", []):
            hostname = host.get("hostname", "")
            parts = hostname.split(".")
            root = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            report["reverse_hosts"].append({
                "ip":       host.get("ip", ""),
                "hostname": hostname,
                "root":     root,
            })

    # Summary stats'''
    rm = rm.replace("    # Summary stats", block)
    applied.append("Added reverse DNS data loading")
elif 'data.get("reverse")' in rm:
    applied.append("reverse data loading already present (skipped)")
else:
    warnings.append("Could not find '# Summary stats' marker")

if "def generate_change_report" not in rm:
    func = '''

# ----------------------------------------------
#  CHANGE REPORT GENERATOR (for monitor module)
# ----------------------------------------------

def generate_change_report(changes, target, output_dir=RESULTS_DIR):
    """Generate an HTML change report from monitor output."""
    print("\\n[*] Generating HTML change report...")
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    try:
        template = env.get_template("changes.html.j2")
    except Exception as e:
        print("[!] Could not load change template:", e)
        return None
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = template.render(target=target, generated=generated, changes=changes)
    safe_target = target.replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, "changes_" + safe_target + "_" + timestamp + ".html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print("    [+] Change report saved to", output_path)
    return output_path
'''
    rm = rm.rstrip() + "\n" + func + "\n"
    applied.append("Added generate_change_report function")
else:
    applied.append("generate_change_report already present (skipped)")

try:
    ast.parse(rm)
    with open(rm_path, "w", encoding="utf-8") as f:
        f.write(rm)
    applied.append("report_module.py validated and saved")
except SyntaxError as e:
    warnings.append("SYNTAX ERROR - did NOT save: " + str(e))

print("\nAPPLIED:")
for a in applied:
    print("  [+]", a)
if warnings:
    print("\nWARNINGS:")
    for w in warnings:
        print("  [!]", w)
print("="*55)

# ── 3. Patch main report.html.j2 to add reverse DNS section ──
tmpl_path = "templates/report.html.j2"
if os.path.exists(tmpl_path):
    with open(tmpl_path, "r", encoding="utf-8") as f:
        tmpl = f.read()
    if "report.reverse_hosts" not in tmpl and "Detected Technologies" in tmpl:
        reverse_html = '''    <!-- Reverse DNS / Infrastructure -->
    {% if report.reverse_hosts %}
    <div class="section">
      <div class="section-title">Reverse DNS &amp; Infrastructure</div>
      <table>
        <thead><tr><th>IP Address</th><th>Hostname</th><th>Root Domain</th></tr></thead>
        <tbody>
          {% for host in report.reverse_hosts %}
          <tr>
            <td class="mono">{{ host.ip }}</td>
            <td class="mono">{{ host.hostname }}</td>
            <td>{{ host.root }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    <!-- Detected Technologies'''
        tmpl = tmpl.replace("    <!-- Detected Technologies", reverse_html, 1)
        with open(tmpl_path, "w", encoding="utf-8") as f:
            f.write(tmpl)
        print("  [+] Added reverse DNS section to report.html.j2")
    elif "report.reverse_hosts" in tmpl:
        print("  [+] reverse section already in template (skipped)")
    else:
        print("  [!] Could not find Technologies comment in template (add manually)")
else:
    print("  [!] templates/report.html.j2 not found")

# ── 4. Hook reverse_dns.py to generate report ──
rev_path = "modules/reverse_dns.py"
if os.path.exists(rev_path):
    with open(rev_path, "r", encoding="utf-8") as f:
        rev = f.read()
    if "report_module" not in rev and "return final_results" in rev:
        hook = '''    # Generate HTML report from this reverse scan
    try:
        from modules import report_module
        report_data = report_module.build_report_data({"reverse": final_results})
        report_data["target"] = target
        report_module.generate_html_report(report_data, output_dir)
    except Exception as e:
        print("[!] Could not generate HTML report:", e)

    return final_results'''
        rev = rev.replace("    return final_results", hook, 1)
        import ast as _ast
        try:
            _ast.parse(rev)
            with open(rev_path, "w", encoding="utf-8") as f:
                f.write(rev)
            print("  [+] Hooked reverse_dns.py to generate HTML report")
        except SyntaxError as e:
            print("  [!] reverse_dns hook syntax error, skipped:", e)
    else:
        print("  [+] reverse_dns already hooked or marker missing (skipped)")

# ── 5. Hook monitor.py to generate change report ──
mon_path = "modules/monitor.py"
if os.path.exists(mon_path):
    with open(mon_path, "r", encoding="utf-8") as f:
        mon = f.read()
    if "generate_change_report" not in mon and 'print(f"\\n[*] Change report saved to {report_path}")' in mon:
        hook = '''print(f"\\n[*] Change report saved to {report_path}")
            try:
                from modules import report_module
                report_module.generate_change_report(changes, target, output_dir)
            except Exception as e:
                print("[!] Could not generate HTML change report:", e)'''
        mon = mon.replace('print(f"\\n[*] Change report saved to {report_path}")', hook, 1)
        import ast as _ast2
        try:
            _ast2.parse(mon)
            with open(mon_path, "w", encoding="utf-8") as f:
                f.write(mon)
            print("  [+] Hooked monitor.py to generate HTML change report")
        except SyntaxError as e:
            print("  [!] monitor hook syntax error, skipped:", e)
    else:
        print("  [+] monitor already hooked or marker missing (skipped)")

print("="*55)
print("All HTML output patches complete.")
print("="*55)
