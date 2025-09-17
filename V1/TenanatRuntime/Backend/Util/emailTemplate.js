function otpEmailTemplate({ name, otp }) {
    return `
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Your OTP</title>
    </head>
    <body style="margin:0;font-family:Arial,Helvetica,sans-serif;background:#f4f7ff;">
      <!-- Outer wrapper -->
      <table width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="#f4f7ff">
        <tr>
          <td align="center">
            <!-- Banner background -->
            <table width="680" cellpadding="0" cellspacing="0" border="0" 
              background="https://archisketch-resources.s3.ap-northeast-2.amazonaws.com/vrstyler/1661497957196_595865/email-template-background-banner"
              style="background-size:cover;background-repeat:no-repeat;background-position:top center;border-radius:0 0 30px 30px;overflow:hidden;">
              
              <!-- Header bar -->
              <tr>
                <td colspan="2" bgcolor="#000000" style="padding:20px 30px;border-radius:0 0 30px 30px;">
                  <table width="100%" border="0" cellspacing="0" cellpadding="0">
                    <tr>
                      <td align="left" style="display:flex;align-items:center;">
                        <img src="https://drive.usercontent.google.com/download?id=1C7rV6VXtdKo7HxrGXDPfDOgnY0UNR9hj&export=download&authuser=0" 
                            alt="StockSense" height="40" style="display:inline-block;vertical-align:middle;" />
                      </td>
                      
                      <span align="left" style="color:#ffffff;font-size:18px;font-weight:bold;vertical-align:middle;">
                        StockSense
                      </span>

                      <td align="right" style="color:#ffffff;font-size:14px;">
                        ${new Date().toDateString()}
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>

              <!-- White box (content card) -->
              <tr>
                <td colspan="2" style="padding:40px 30px 20px 30px;">
                  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;border-radius:20px;padding:50px;text-align:center;">
                    <tr>
                      <td>
                        <h1 style="margin:0;font-size:24px;color:#1f1f1f;">Your OTP</h1>
                        <p style="margin-top:15px;font-size:16px;">Hey ${
                            name || "User"
                        },</p>
                        <p style="margin-top:15px;color:#434343;">
                          Use the following OTP to verify your email. It is valid for <b>5 minutes</b>.
                        </p>
                        <p style="margin-top:30px;font-size:36px;font-weight:700;letter-spacing:20px;color:#ba3d4f;">
                          ${otp}
                        </p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>

              <!-- Support + Footer inside clear box -->
              <tr>
                <td colspan="2" style="padding:0 30px 40px 30px;">
                  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;border-radius:20px;padding:20px;text-align:center;">
                    <tr>
                      <td style="font-size:14px;color:#434343;">
                        Need help? Ask at 
                        <a href="mailto:support@vishalhq.in" style="color:#499fb6;text-decoration:none;">
                          support@vishalhq.in
                        </a> 
                        or visit our 
                        <a href="https://stocksense.vishalhq.in/help" style="color:#499fb6;text-decoration:none;" target="_blank">
                          Help Center
                        </a>.
                      </td>
                    </tr>
                    <tr>
                      <td style="padding-top:15px;font-size:14px;color:#434343;">
                        © ${new Date().getFullYear()} StockSense. All rights reserved.
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>

            </table>
          </td>
        </tr>
      </table>
    </body>
  </html>
  `;
}

module.exports = { otpEmailTemplate };
