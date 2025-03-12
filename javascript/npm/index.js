const express = require('express');
const marked = require('marked');
const serialize = require('node-serialize');
const _ = require('lodash');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());

// Vulnerable marked usage (XSS vulnerability)
app.get('/render-markdown', (req, res) => {
    const userInput = req.query.markdown || '';
    const rendered = marked(userInput); // Marked < 0.3.19 has XSS vulnerabilities
    res.send(rendered);
});

// Vulnerable lodash usage (Prototype Pollution)
app.post('/merge-data', (req, res) => {
    const obj1 = req.body.obj1 || {};
    const obj2 = req.body.obj2 || {};
    const merged = _.merge({}, obj1, obj2); // Lodash 4.17.11 has prototype pollution
    res.json(merged);
});

// Vulnerable node-serialize usage (Remote Code Execution)
app.post('/deserialize', (req, res) => {
    const userInput = req.body.data;
    const deserialized = serialize.unserialize(userInput); // node-serialize has RCE vulnerability
    res.json({ result: deserialized });
});

// Vulnerable mongoose connection (Man in the Middle attack possible)
mongoose.connect('mongodb://localhost/test', { useNewUrlParser: true })
    .then(() => console.log('Connected to MongoDB...'))
    .catch(err => console.error('Could not connect to MongoDB...', err));

const port = 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
