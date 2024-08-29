import * as nodemailer from 'nodemailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      auth: {
        user: 'bennett51@ethereal.email',
        pass: 'AfYYQempDaq3afWvky',
      },
    });
  }

  async sendPasswordResetEmail(to: string, token: string) {
    const resetLink = `http://yourapp.com/reset-password?token=${token}`;
    const mailOptions = {
      from: 'Auth-backend service',
      to: to,
      subject: 'Password Reset Request',
      html: `<p> You requested a password reset. Click the link below to reset your password:</p><a href=${resetLink}>Click here</a><p>`,
    };
    await this.transporter.sendMail(mailOptions);
  }
}
