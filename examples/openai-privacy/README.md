# OpenAI privacy boundary

This runnable example uses an OpenAI-compatible fake client so you can see the
privacy boundary without an API key. `wrapOpenAI` sees the same
`chat.completions.create` interface exposed by the official SDK.

From the repository root:

```bash
npm run build
npm --prefix examples/openai-privacy install
npm --prefix examples/openai-privacy start
```

The model-facing prompt contains an opaque placeholder. The application-facing
reply contains the restored email address.

With the official client, keep the wrapper in the same place:

```js
import OpenAI from 'openai';
import { wrapOpenAI } from 'flare-redact/llm';

const openai = wrapOpenAI(new OpenAI());
```
