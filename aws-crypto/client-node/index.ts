import {
  Handler,
  APIGatewayEvent,
  APIGatewayAuthorizerEvent,
  Context,
  Callback,
} from "aws-lambda";

import {
  KmsKeyringNode,
  buildClient,
  CommitmentPolicy
} from "@aws-crypto/client-node";

/** encrypt/decrypt関数の作成 */
const { decrypt } = buildClient(
  CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
);

/** データキーの生成に使うKMS CMK */
const generatorKeyId = "arn:aws:kms:ap-northeast-1:${ACCOUNT}:alias/${KEY ALIAS}"

/** 暗号化に使うCMK */
const keyIds = [
  'arn:aws:kms:ap-northeast-1:${ACCOUNT}:key/${KEY ID}',
]

/** keyringの作成 */
const keyring = new KmsKeyringNode({generatorKeyId, keyIds});

/** アプリ識別キーのヘッダシンボル名 */
const X_API_KEY_SYMBOL = "X-api-key";
/** アプリ認証キーのヘッダシンボル名 */
const IOI_API_KEY_SYMBOL = "X-APP-KEY";

/**
 * APIGatewayイベントに対するハンドラ.
 * @param event API Gatewayから通知されるイベント.
 * @param context イベントのcallback context.
 * @param callback コールバック関数.
 */
export const handler: Handler = async function (event: APIGatewayEvent,
    context: Context,
    callback: Callback
  ) {
    // event情報のtrace
    console.log(`request: ${JSON.stringify(event)}`);
    const apiKey = event.headers[X_API_KEY_SYMBOL];
    const authorizationKey = event.headers[IOI_API_KEY_SYMBOL];
    // APIGatewayAuthorizerEventにcastする.
    const authorizerEvent = event as any as APIGatewayAuthorizerEvent;
    // APIキー/認証キーがなかったり、APIGatewayAuthorizerEventではなかった場合.
    if (!authorizationKey || !apiKey || !authorizerEvent.methodArn) {
      authError(callback, {message: "Can not find token.", e: new Error("APIキーがありません.")});
      return;
    }
    const decryptedText = await decryptText(authorizationKey);
    console.log(`text: ${decryptedText}`);
    callback(null, await generatePolicy(authorizerEvent.methodArn));
}

/**
 * KMSを用いてテキストを復号する.
 * @param encryptedText KMSによって暗号化された文字列.
 * @returns 復号された文字列.
 */
const decryptText = async (encryptedText: string) => {
  const buffer = Buffer.from(encryptedText, "base64");
  return (await decrypt(keyring, buffer)).plaintext.toString("ascii");
}

/**
 * ポリシードキュメントを返却する.<br>
 * https://docs.aws.amazon.com/ja_jp/IAM/latest/UserGuide/reference_policies_elements.html
 *
 * @param methodArn 受信したメソッドリクエストのARN
 */
const generatePolicy = async (methodArn: string) => {
  return {
    principalId: 1,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          Action: "execute-api:Invoke",
          Effect: "Allow",
          Resource: methodArn
        }
      ]
    },
    context: {
    }
  };
}

/**
 * 認証エラーが発生した場合の共通関数.
 *
 * @param callback Lambda Callback.
 * @param options error時のオプション情報.
 */
const authError = (callback: Callback, options: {
  message: string
  e?: Error
}) => {
  callback(`Error: ${options.message} ${options.e?.stack}`)
}
