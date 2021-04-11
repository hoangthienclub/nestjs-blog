import { Request } from "express";
import User from "src/users/user.entity";
Request

interface RequestWithUser extends Request {
  user: User;
}

export default RequestWithUser;