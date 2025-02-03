require('dotenv').config(); 
const express = require('express');
const bodyParser = require('body-parser');
const routes = require('./routes');

const app = express();
app.use(bodyParser.json());

//Main Routes
app.use('/api', routes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`EagleDocsBE Listening On Port -> [${PORT}]`);
});
