const fs = require('fs');
const path = require('path');

const target = process.argv[2] || path.join(__dirname, '..', 'config.js');

const config = {
    OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY || '',
    OPENROUTER_MODEL: process.env.OPENROUTER_MODEL || 'openai/gpt-4o-mini'
};

fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(
    target,
    'window.APP_CONFIG = ' + JSON.stringify(config, null, 2) + ';\n',
    'utf8'
);

console.log('Wrote', target, config.OPENROUTER_API_KEY ? '(OpenRouter key present)' : '(no OpenRouter key)');
