## コンパイル方法
```
cargo add tokio --features="full"
cargo add sha1
cargo add base64

cargo build
cargo run
```

`cargo run` した後に、`text.html` をブラウザに読み込ませる。  
そうすると、ブラウザのコンソールにメッセージが表示されて、websocket による通信が実行されたことが分かる。  
ただし、`test.html` の４行目の new WebSocket のアドレスを適当に調整してね。

あと、`cargo test` で、テストを実行すると、Rust の lifetime について知識が増えるかも。  
`f(&mut s)` を実行すると、`&mut s` の参照が解放されなくなる不具合の原因は、いまだに不明。
