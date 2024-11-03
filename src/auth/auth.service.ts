import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/auth.entity';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { response } from 'express';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async create(createAuthDto: CreateAuthDto) {
    const { email, password, username } = createAuthDto;
    const emailInUse = await this.userModel.findOne({ email });
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await this.userModel.create({
      email,
      password: hashedPassword,
      username,
    });

    return {
      success: true,
      message: 'Register successful',
    };

  }

  async login(credentails: LoginDto) {
    const { email, password } = credentails;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const token = await this.generateUserToken(user._id);

    const { password: string, ...others } = user.toObject();

    return {
      success: true,
      message: "Login successful",
      data: {
        ...others
      },
      token
    };
  }

  async generateUserToken(userId) {
    const acccessToken = this.jwtService.sign({userId}, {expiresIn: '1h'});

    return acccessToken
  }

  async getProfile(id: string) {
    const user = await this.userModel.findById(id);
    if (!user) {
      throw new BadRequestException('User not found');
    }

    const { password: string, ...others } = user.toObject();

    return {
      success: true,
      data: {
        ...others
      }
    };
  }
  
  logOut() {
    return {
      success: true,
      message: 'Logout successful',
    };
  }

}
