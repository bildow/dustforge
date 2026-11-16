// Realistic newsletter shapes (simplified from common public boilerplates): what a pane gets.
module.exports = {
  'litmus-style boilerplate': `<!doctype html><html><head><meta charset="utf-8"><style type="text/css">
body,table,td,a{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%}table,td{mso-table-lspace:0pt;mso-table-rspace:0pt}
img{-ms-interpolation-mode:bicubic;border:0;height:auto;line-height:100%;outline:none;text-decoration:none}
table{border-collapse:collapse !important}body{height:100% !important;margin:0 !important;padding:0 !important;width:100% !important}
a[x-apple-data-detectors]{color:inherit !important;text-decoration:none !important;font-size:inherit !important;font-family:inherit !important;font-weight:inherit !important;line-height:inherit !important}
u + #body a{color:inherit;text-decoration:none;font-size:inherit;font-family:inherit;font-weight:inherit;line-height:inherit}
#MessageViewBody a{color:inherit;text-decoration:none;font-size:inherit;font-family:inherit;font-weight:inherit;line-height:inherit}
@media screen and (max-width:600px){.mobile-hide{display:none !important}.img-max{max-width:100% !important;width:100% !important;height:auto !important}.responsive-table{width:100% !important}h1{font-size:28px !important}}
</style></head><body id="body" style="margin:0;padding:0;background-color:#f4f4f4">
<div style="display:none;font-size:1px;color:#fefefe;line-height:1px;font-family:Helvetica,Arial,sans-serif;max-height:0px;max-width:0px;opacity:0;overflow:hidden">Preheader teaser text</div>
<table border="0" cellpadding="0" cellspacing="0" width="100%"><tr><td bgcolor="#f4f4f4" align="center">
<table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width:600px" class="responsive-table"><tr>
<td bgcolor="#ffffff" align="left" style="padding:20px 30px;color:#666666;font-family:Helvetica,Arial,sans-serif;font-size:16px;line-height:25px">
<h1 style="font-size:32px;font-weight:400;margin:0;color:#111111">Welcome aboard</h1><p style="margin:0">Your account is ready. Here is what to do next.</p></td></tr>
<tr><td align="center" style="border-radius:3px" bgcolor="#FFA73B"><a href="https://shop.example/start" style="font-size:20px;font-family:Helvetica,Arial,sans-serif;color:#ffffff;text-decoration:none;padding:15px 25px;border-radius:2px;border:1px solid #FFA73B;display:inline-block">Get started</a></td></tr>
<tr><td bgcolor="#f4f4f4" align="left" style="padding:30px;color:#666666;font-family:Helvetica,Arial,sans-serif;font-size:14px;line-height:18px"><p style="margin:0">You received this because you signed up. <a href="https://shop.example/u" style="color:#111111;font-weight:700">Unsubscribe</a>.</p></td></tr>
</table></td></tr></table></body></html>`,
  'hybrid columns (font-size:0 wrapper)': `<table width="100%"><tr><td style="font-size:0;text-align:center"><!--[if mso]><table><tr><td width="300"><![endif]-->
<div style="display:inline-block;width:100%;max-width:300px;vertical-align:top"><p style="font-size:16px;font-family:Arial;color:#222222;margin:0">Left column news</p></div>
<div style="display:inline-block;width:100%;max-width:300px;vertical-align:top"><p style="font-size:16px;font-family:Arial;color:#222222;margin:0">Right column offers</p></div>
<!--[if mso]></td></tr></table><![endif]--></td></tr></table>`,
  'plain transactional': `<html><body style="font-family:Arial,sans-serif;font-size:14px;color:#333333"><p>Hi Aaron,</p><p>Your order #1234 has shipped. Track it at <a href="https://shop.example/t/1234">our site</a>.</p><p style="color:#999999;font-size:12px">Shop Example Inc.</p></body></html>`,
  'class-styled with descendant rules': `<html><head><style>.wrapper{background-color:#ffffff}.footer p{color:#8a8a8a;font-size:12px}.header{background:#1d3557}.header h1{color:#f1faee}.btn a{color:#ffffff}.btn{background-color:#e63946}</style></head><body>
<div class="wrapper"><div class="header"><h1>Weekly digest</h1></div><p>Three stories this week.</p><div class="btn"><a href="https://news.example/r">Read more</a></div><div class="footer"><p>Unsubscribe any time.</p></div></div></body></html>`,
  'google fonts link': `<html><head><link href="https://fonts.googleapis.com/css?family=Lato" rel="stylesheet"><style>body{font-family:Lato,Arial}</style></head><body><p>Hello from a newsletter with a web font.</p></body></html>`,
  'dark-mode media query': `<html><head><style>.body{background:#ffffff;color:#111111}@media (prefers-color-scheme: dark){.body{background:#111111 !important;color:#eeeeee !important}}</style></head><body class="body"><p>Dark mode aware content.</p></body></html>`,
  'hero image with white text': `<table width="100%"><tr><td background="https://img.example/hero.jpg" style="background:url(https://img.example/hero.jpg) center/cover #333333;padding:40px"><h1 style="color:#ffffff;font-family:Arial">Big sale this weekend</h1></td></tr></table><p>Details inside.</p>`,
  'outlook conditional + preheader class': `<html><head><style>.preheader{display:none !important;visibility:hidden;mso-hide:all;font-size:1px;color:#ffffff;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden}</style></head><body><span class="preheader">Hidden teaser</span><!--[if mso]><p>Outlook only</p><![endif]--><p style="color:#202020">Main content here.</p></body></html>`,
};
