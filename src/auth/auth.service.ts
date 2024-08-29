import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh.schema';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { ResetToken } from './schemas/reset-token.schema';
import { MailService } from 'src/services/mail.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name)
    private ResetTokenModel: Model<ResetToken>,
    private jwtService: JwtService,
    private mailService: MailService,
  ) {}

  async signup(signupData: SignupDto) {
    const { email, password, name } = signupData;
    console.log('signupData', signupData);
    // TODO:Check if email is in use
    const emailInUse = await this.UserModel.findOne({
      email: email,
    });
    console.log('email in use', emailInUse);
    if (emailInUse) {
      throw new BadRequestException('email already in use');
    }

    // TODO: Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // TODO: create your document and save in mongodb
    await this.UserModel.create({
      name,
      email,
      password: hashedPassword,
    });
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    //TODO: Find if user exists by email
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('user does not exist');
    }
    //TODO:compare entered password with existing password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('wrong credentials');
    }
    //TODO:generate jwt token
    return this.generateUserTokens(user._id);
  }

  async generateUserTokens(userId) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' });
    const refreshToken = uuidv4();
    await this.storeRefreshToken(refreshToken, userId);
    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(token: string, userId) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);
    await this.RefreshTokenModel.updateOne(
      { userId },
      { $set: { expiryDate, token } },
      { upsert: true },
    );
  }

  async refreshTokens(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOne({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('Refresh token is invalid');
    }
    return this.generateUserTokens(token.userId);
  }

  async changePassword(userId, oldPassword: string, newPassword: string) {
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found...');
    }

    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('wrong credentials');
    }

    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = newHashedPassword;
    await user.save();
  }

  async forgotPassword(email: string) {
    const user = await this.UserModel.findOne({ email });
    if (user) {
      const resetToken = nanoid(64);
      const expiryDate = new Date();
      expiryDate.setHours(expiryDate.getHours() + 1);
      await this.ResetTokenModel.create({
        token: resetToken,
        userId: user._id,
        expiryDate: expiryDate,
      });
      await this.mailService.sendPasswordResetEmail(email, resetToken);
    }

    return { message: 'recovery link sent via email' };
  }

  async resetPassword(newPassword: string, resetToken: string) {
    const token = await this.ResetTokenModel.findOneAndDelete({
      token: resetToken,
      expiryDate: { $gte: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('Invalid link');
    }

    const user = await this.UserModel.findById(token.userId);
    if (!user) {
      throw new UnauthorizedException('user not found');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
  }
}
