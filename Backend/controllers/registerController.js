const User = require("../model/User");
const bcrypt = require("bcrypt");

const handleNewUser = async (req, res) => {
  const { user, pwd } = req.body;
  if (!user || !pwd) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }
  //Check for duplicate usernames in the db
  const duplicate = await User.findOne({ username: user }).exec();
  if (duplicate) {
    return res.sendStatus(409); //conflict
  }
  try {
    //encrypt the password
    const hashedPwd = await bcrypt.hash(pwd, 10);

    //create ans store new user
    const result = await User.create({
      username: user,
      password: hashedPwd,
    });

    // //Another way
    // const newUser = new User();
    // newUser.username = "user";
    // const result1 = await newUser.save();
    // //            (or)
    // const newUser2 = new User({
    //   username: user,
    //   password: hashedPwd,
    // });
    // const result2 = await newUser.save();

    res.status(201).json({ success: `new User ${user} created!` });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = { handleNewUser };
