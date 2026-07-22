import { wrapOpenAI } from 'flare-redact/llm';

let promptSeenByModel = '';

// This dependency-free fake has the same chat.completions.create shape as the
// official OpenAI client, so the example is runnable without an API key.
const openai = {
  chat: {
    completions: {
      async create(params) {
        promptSeenByModel = params.messages[0].content;
        const placeholder = promptSeenByModel.match(/\[FR_EMAIL_[0-9a-f]{24}\]/)?.[0];
        return {
          choices: [{
            message: {
              role: 'assistant',
              content: `I will reference ${placeholder} without seeing the original address.`,
            },
          }],
        };
      },
    },
  },
};

wrapOpenAI(openai);

const response = await openai.chat.completions.create({
  model: 'your-model',
  messages: [{ role: 'user', content: 'Draft an email to alice@example.com' }],
});

console.log(JSON.stringify({
  promptSeenByModel,
  responseReturnedToApp: response.choices[0].message.content,
}, null, 2));
