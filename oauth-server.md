
# go-auth2源码分析

[toc]

## server部分

### Server 结构体


server/server.go 中可以看到一个Server struct的信息：
```
// Server Provide authorization server
type Server struct {
	Config                       *Config
	Manager                      oauth2.Manager
	ClientInfoHandler            ClientInfoHandler
	ClientAuthorizedHandler      ClientAuthorizedHandler
	ClientScopeHandler           ClientScopeHandler
	UserAuthorizationHandler     UserAuthorizationHandler
	PasswordAuthorizationHandler PasswordAuthorizationHandler
	RefreshingValidationHandler  RefreshingValidationHandler
	RefreshingScopeHandler       RefreshingScopeHandler
	ResponseErrorHandler         ResponseErrorHandler
	InternalErrorHandler         InternalErrorHandler
	ExtensionFieldsHandler       ExtensionFieldsHandler
	AccessTokenExpHandler        AccessTokenExpHandler
	AuthorizeScopeHandler        AuthorizeScopeHandler
}

```

server/server.go中 调用NewServe()创建一个server对象 ：

```
// 这里可以看到，创建一个server需要传进一个config信息，已经一个Manager对象
// NewServer create authorization server
func NewServer(cfg *Config, manager oauth2.Manager) *Server {
	srv := &Server{
		Config:  cfg,
		Manager: manager,
	}

	// default handler
	srv.ClientInfoHandler = ClientBasicHandler

	srv.UserAuthorizationHandler = func(w http.ResponseWriter, r *http.Request) (string, error) {
		return "", errors.ErrAccessDenied
	}

	srv.PasswordAuthorizationHandler = func(username, password string) (string, error) {
		return "", errors.ErrAccessDenied
	}
	return srv
}

```
####  NewServe函数使用的config信息
server/config.go可以看到Config struct主要包含的内容：

```
// config 结构体主要定义了token的类型，已经允许的授权模式等信息
// Config configuration parameters
type Config struct {
	TokenType                   string                // token type
	AllowGetAccessRequest       bool                  // to allow GET requests for the token
	AllowedResponseTypes        []oauth2.ResponseType // allow the authorization type
	AllowedGrantTypes           []oauth2.GrantType    // allow the grant type
	AllowedCodeChallengeMethods []oauth2.CodeChallengeMethod
	ForcePKCE                   bool
}

// 这里调用NewConfig会创建一个默认的config对象，
// 默认的token type 为 Bearer
// 默认4中授权模式都允许，包括我们即将使用的authorizationCode授权码模式
// 默认的ForcePKCE为false 
// NewConfig create to configuration instance
func NewConfig() *Config {
	return &Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{oauth2.Code, oauth2.Token},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.AuthorizationCode,
			oauth2.PasswordCredentials,
			oauth2.ClientCredentials,
			oauth2.Refreshing,
		},
		AllowedCodeChallengeMethods: []oauth2.CodeChallengeMethod{
			oauth2.CodeChallengePlain,
			oauth2.CodeChallengeS256,
		},
	}
}

```


####  NewServe函数使用的Manager信息

manage/manager.go可以看到Manager结构体

```
type Manager struct {
   codeExp           time.Duration  // 指定auth code的过期时间
   gtcfg             map[oauth2.GrantType]*Config  // 指定不同auth模式的基本配置相关
   rcfg              *RefreshingConfig   // 刷新token的相关配置
   validateURI       ValidateURIHandler  // 这个函数用来验证请求url参数 合法性，
   authorizeGenerate oauth2.AuthorizeGenerate   // 这个interfaced定义了创建auth code的方法
   accessGenerate    oauth2.AccessGenerate   // 这个interface包含了创建token的方法
   tokenStore        oauth2.TokenStore  //token store interface定了了存放token的相关逻辑接口
   clientStore       oauth2.ClientStore  // client store interface 定义了存放和管理授权过的app client_id,client_secret等信息的接口
}

```

##### Manager对象中的generate相关

```
// generate.go中定义了生成auth_code, token相关的接口，需要用户去实现这个接口：
type (
   // GenerateBasic provide the basis of the generated token data
   GenerateBasic struct {
      Client    ClientInfo
      UserID    string
      CreateAt  time.Time
      TokenInfo TokenInfo
      Request   *http.Request
   }

   // AuthorizeGenerate generate the authorization code interface
   AuthorizeGenerate interface {
      Token(ctx context.Context, data *GenerateBasic) (code string, err error)
   }

   // AccessGenerate generate the access and refresh tokens interface
   AccessGenerate interface {
      Token(ctx context.Context, data *GenerateBasic, isGenRefresh bool) (access, refresh string, err error)
   }
)
```

##### Manager对象中的store相关

```
client store需要实现的接口：
ClientStore interface {
   // according to the ID for the client information
   GetByID(ctx context.Context, id string) (ClientInfo, error)
}


token store需要实现的接口：
TokenStore interface {
   // create and store the new token information
   Create(ctx context.Context, info TokenInfo) error

   // delete the authorization code
   RemoveByCode(ctx context.Context, code string) error

   // use the access token to delete the token information
   RemoveByAccess(ctx context.Context, access string) error

   // use the refresh token to delete the token information
   RemoveByRefresh(ctx context.Context, refresh string) error

   // use the authorization code for token information data
   GetByCode(ctx context.Context, code string) (TokenInfo, error)

   // use the access token for token information data
   GetByAccess(ctx context.Context, access string) (TokenInfo, error)

   // use the refresh token for token information data
   GetByRefresh(ctx context.Context, refresh string) (TokenInfo, error)
}

```

### 实际创建完备Server对象的过程

```
	// NewDefaultManager 创建了一个manger对象，并实现AuthorizeGenerate，AccessGenerate 接口赋值给相应的对象
	manager := manage.NewDefaultManager()
    
    // 设置验证码模式的默认配置，如超时时间，是否开启刷新token等
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store 初始化， 这里使用默认提供的内存 store存放token信息
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// 用户也可以调用相应的map 方法，去自己去实现自定义的generate接口实现
	// manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
    // manager.MapAccessGenerate(generates.NewAccessGenerate())

	// 使用store/client.go默认提供的 clientStore 接口实现去初始化一个clientStore
	clientStore := store.NewClientStore()
	clientStore.Set(idvar, &models.Client{
		ID:     idvar,
		Secret: secretvar,
		Domain: domainvar,
	})
    // 然后使用Map方法把新创建的clientstore连接到manager
	manager.MapClientStorage(clientStore)
	
    // 最终调用NewServer 生成一个能够处理oauth2逻辑的server对象
	srv := server.NewServer(server.NewConfig(), manager)
```

#### store初始化map函数和must函数的区别

在manager 的clientstore, tokenstore 属性赋值的时候，存在两个函数，他们的区别是 MUst会多传入一个err 参数，如果err参数不为nil,则直接panic， 代码如下：
```

// MapClientStorage mapping the client store interface
func (m *Manager) MapClientStorage(stor oauth2.ClientStore) {
	m.clientStore = stor
}

// MustClientStorage mandatory mapping the client store interface
func (m *Manager) MustClientStorage(stor oauth2.ClientStore, err error) {
	if err != nil {
		panic(err.Error())
	}
	m.clientStore = stor
}

```

使用场景：

```
// 这里NewMemoryTokenStore()先创建一个token store,在调用must方法，可以直接处理这里NewMemoryTokenStore()函数返回报错的情况，直接在must函数中painc, 使得主流程处理代码更清晰
	manager.MustTokenStorage(store.NewMemoryTokenStore())

```

#### 实现一个自定义的的clientstore
clientstore提供了授权app的clientinfo管理功能的抽象
oauth2包默认提供的是基于内存的clientstore实现（参见store/client.go），使用者可以根据自己需要去实现自己的clientstore 去存储授权client app信息，同时可以扩展功能，如权限和角色等功能。 基本流程，自定义要给结构体A，为结构体A添加GetByID方法， 定一个NewClientStore函数，返回一个A的实例对象。

```
	ClientStore interface {
		// according to the ID for the client information
		GetByID(ctx context.Context, id string) (ClientInfo, error)
	}

```

官方参考：

```
// 返回自定义的client store对象
// NewClientStore create client store
func NewClientStore() *ClientStore {
	return &ClientStore{
		data: make(map[string]oauth2.ClientInfo),
	}
}


// 先定义一个store结构体
// ClientStore client information store
type ClientStore struct {
	sync.RWMutex
	data map[string]oauth2.ClientInfo
}

// 这里实现了ClientStore接口必须的GetByID方法
// GetByID according to the ID for the client information
func (cs *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	cs.RLock()
	defer cs.RUnlock()

	if c, ok := cs.data[id]; ok {
		return c, nil
	}
	return nil, errors.New("not found")
}

// 这里扩展clientstore，实现了往store中增加 app clientinfo的方法
// Set set client information
func (cs *ClientStore) Set(id string, cli oauth2.ClientInfo) (err error) {
	cs.Lock()
	defer cs.Unlock()

	cs.data[id] = cli
	return
}


```


#### 实现一个自定义的的token store
不同app的用户授权通过oauth2进行统一认证的时候，token store 提供了相关功能的抽象，包括auth code的生成/存储， token的生成/存储.

如果要实现一个自定义的token store就需要实现 TokenStore接口中声明的方法：

```
	TokenStore interface {
		// create and store the new token information
        // create 提供创建和存储新token的功能
		Create(ctx context.Context, info TokenInfo) error
        
        // 删除存储的auth code info
		// delete the authorization code
		RemoveByCode(ctx context.Context, code string) error

		// 根据access_token删除整个token信息
		// use the access token to delete the token information
		RemoveByAccess(ctx context.Context, access string) error
		
        // 根据refreshToken删除token信息
		// use the refresh token to delete the token information
		RemoveByRefresh(ctx context.Context, refresh string) error

		// 使用auth_code获取token信息
		// use the authorization code for token information data
		GetByCode(ctx context.Context, code string) (TokenInfo, error)

		//使用access_token获取完整token信息
		// use the access token for token information data
		GetByAccess(ctx context.Context, access string) (TokenInfo, error)
		
        // 使用refresh_token获取完整token信息
		// use the refresh token for token information data
		GetByRefresh(ctx context.Context, refresh string) (TokenInfo, error)
	}

```

由于接口需要实现的方法过多，这里不再贴出实现的源代码，oauth2包store/token.go实现了一个基于buntdb去实现的tokenstore, NewMemoryTokenStore()指定使用内存存储， 如果想换成buntdb的本地文件存储，可以调用NewFileTokenStore(filename string)去创建本地文件存储。

另外，如果想基于redis创建token store,可以参考[这里](https://github.com/go-oauth2/redis)

```
	// manager token store in redis
	manager.MapTokenStorage(oredis.NewRedisStore(&redis.Options{
		Addr: "127.0.0.1:6379",
		DB: 15,
	}))

	// manager token store in memory
	manager.MustTokenStorage(store.NewMemoryTokenStore())
    
    // manage token store in file
    manager.MustTokenStorage(store.NewFileTokenStore("hellotoken"))
    
```


### auth server处理认证请求的核心过程

#### 处理auth请求

HandleAuthorizeRequest函数会接受用户请求，处理后返回对应细心给客户端，主要步骤如下

* 1.调用ValidationAuthorizeRequest函数校验请求参数，生成标准的AuthorizeRequest对象
* 2.调用UserAuthorizationHandler函数获取当前请求的user_id信息，更新AuthorizeRequest对象的UserID信息
* 3. AuthorizeScopeHandler如果指定，则进行AuthorizeRequest对象scope处理
* 4. AccessTokenExpHandler如果指定，则更新AuthorizeRequest对象的token expire信息
* 5. 调用GetAuthorizeToken函数获取token信息，返回为一个实现了TokenInfo接口的对象ti
* 6. 调用GetAuthorizeData获取ti的code信息，并通过redirect函数回复重定向到app callback地址。

```
// HandleAuthorizeRequest the authorization request handling
func (s *Server) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
    
    // 步骤1
	req, err := s.ValidationAuthorizeRequest(r)
	if err != nil {
		return s.redirectError(w, req, err)
	}

	// 步骤2
	// user authorization
	userID, err := s.UserAuthorizationHandler(w, r)
	if err != nil {
		return s.redirectError(w, req, err)
	} else if userID == "" {
		return nil
	}
	req.UserID = userID

	//步骤3
	// specify the scope of authorization
	if fn := s.AuthorizeScopeHandler; fn != nil {
		scope, err := fn(w, r)
		if err != nil {
			return err
		} else if scope != "" {
			req.Scope = scope
		}
	}
	
    // 步骤4
	// specify the expiration time of access token
	if fn := s.AccessTokenExpHandler; fn != nil {
		exp, err := fn(w, r)
		if err != nil {
			return err
		}
		req.AccessTokenExp = exp
	}

	//步骤5
	ti, err := s.GetAuthorizeToken(ctx, req)
	if err != nil {
		return s.redirectError(w, req, err)
	}

      // If the redirect URI is empty, the default domain provided by the client is used.
	if req.RedirectURI == "" {
		client, err := s.Manager.GetClient(ctx, req.ClientID)
		if err != nil {
			return err
		}
		req.RedirectURI = client.GetDomain()
	}

	// 步骤6
	return s.redirect(w, req, s.GetAuthorizeData(req.ResponseType, ti))
}

```

##### GetAuthorizeToken获取tokenInfo过程分析

###### tokenInfo 定义
这里先贴出返回的tokenInfo interface的定义，token中包含了app client信息/auth code信息/acces_token信息/refresh_token信息这几个部分的存取方法定义：

```
	// TokenInfo the token information model interface
	TokenInfo interface {
		New() TokenInfo
		//授权app client相关信息部分
		GetClientID() string
		SetClientID(string)
		GetUserID() string
		SetUserID(string)
		GetRedirectURI() string
		SetRedirectURI(string)
		GetScope() string
		SetScope(string)
        
		// auth code相关处理部分
		GetCode() string
		SetCode(string)
		GetCodeCreateAt() time.Time
		SetCodeCreateAt(time.Time)
		GetCodeExpiresIn() time.Duration
		SetCodeExpiresIn(time.Duration)
		GetCodeChallenge() string
		SetCodeChallenge(string)
		GetCodeChallengeMethod() CodeChallengeMethod
		SetCodeChallengeMethod(CodeChallengeMethod)

		// access token相关处理部分
		GetAccess() string
		SetAccess(string)
		GetAccessCreateAt() time.Time
		SetAccessCreateAt(time.Time)
		GetAccessExpiresIn() time.Duration
		SetAccessExpiresIn(time.Duration)

		// refresh token相关处理部分
		GetRefresh() string
		SetRefresh(string)
		GetRefreshCreateAt() time.Time
		SetRefreshCreateAt(time.Time)
		GetRefreshExpiresIn() time.Duration
		SetRefreshExpiresIn(time.Duration)
	}

```

models/token.go 的Token struct则实现了TokenInfo接口：

```
type Token struct {
	ClientID            string        `bson:"ClientID"`
	UserID              string        `bson:"UserID"`
	RedirectURI         string        `bson:"RedirectURI"`
	Scope               string        `bson:"Scope"`
	Code                string        `bson:"Code"`
	CodeChallenge       string        `bson:"CodeChallenge"`
	CodeChallengeMethod string        `bson:"CodeChallengeMethod"`
	CodeCreateAt        time.Time     `bson:"CodeCreateAt"`
	CodeExpiresIn       time.Duration `bson:"CodeExpiresIn"`
	Access              string        `bson:"Access"`
	AccessCreateAt      time.Time     `bson:"AccessCreateAt"`
	AccessExpiresIn     time.Duration `bson:"AccessExpiresIn"`
	Refresh             string        `bson:"Refresh"`
	RefreshCreateAt     time.Time     `bson:"RefreshCreateAt"`
	RefreshExpiresIn    time.Duration `bson:"RefreshExpiresIn"`
}

```

##### GetAuthorizeToken核心处理逻辑

```
func (s *Server) GetAuthorizeToken(ctx context.Context, req *AuthorizeRequest) (oauth2.TokenInfo, error) {
	...
    // 使用传入的AuthorizeRequest床你看一个TokenGenerateRequest对象
	tgr := &oauth2.TokenGenerateRequest{
		ClientID:            req.ClientID,
		UserID:              req.UserID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		AccessTokenExp:      req.AccessTokenExp,
		Request:             req.Request,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}
    // 调用manager的GenerateAuthToken方法，
	return s.Manager.GenerateAuthToken(ctx, req.ResponseType, tgr)
}

这里跳转到mange/manager.go看下GenerateAuthToken的代码逻辑

// GenerateAuthToken generate the authorization token(code)
func (m *Manager) GenerateAuthToken(ctx context.Context, rt oauth2.ResponseType, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo, error) {
   // GetClient内部调用clientstore的GetByID方法获取授权app client信息
	cli, err := m.GetClient(ctx, tgr.ClientID)
    ...
	ti := models.NewToken()  // 创建一个新的token对象
	ti.SetClientID(tgr.ClientID) // 设置token的client_id信息
	ti.SetUserID(tgr.UserID)     // 设置token的userid info
	ti.SetRedirectURI(tgr.RedirectURI) // 设置token的回调地址
	ti.SetScope(tgr.Scope)  // 设置token的 scope信息

	createAt := time.Now()
	td := &oauth2.GenerateBasic{
		Client:    cli,
		UserID:    tgr.UserID,
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}
	switch rt {
	case oauth2.Code:
		...
        // 如果是response_type是code,表示返回auth code
        // 就调用m.authorizeGenerate.Token生成code 
		tv, err := m.authorizeGenerate.Token(ctx, td)
		ti.SetCode(tv) //将生成的token auth code写入token info
	case oauth2.Token:
		...
        // creential模式使用
        //不经过auth返回code的步骤，直接一步到位返回access_token 
		// 如果传入的response_type是token,表示返回access_token信息
        // 则调用m.accessGenerate.Token 生成 access_token, refresh_token
		tv, rv, err := m.accessGenerate.Token(ctx, td, icfg.IsGenerateRefresh)
		ti.SetAccess(tv)  // access_token写入token info
		if rv != "" {
			ti.SetRefresh(rv) // 如果有生成refresh_token，则写入token info
		}
	}
	//调用tokenstore的create方法把完整tokeninfo保存到tokenstore中
	err = m.tokenStore.Create(ctx, ti)
	if err != nil {
		return nil, err
	}
    // 返回最终生成的token info信息
	return ti, nil
}


```


#### 处理获取token请求
在授权码模式下，oauth2 server返回auth code给客户端后，客户端可以发送请求带上code信息去获取完整的token info信息,这个处理逻辑入口是调用HandleTokenRequest函数：

```
// HandleTokenRequest token request handling
func (s *Server) HandleTokenRequest(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	
    // 请求参数校验，通过后返回grant_type, TokenGenerateRequest对象tgr
    // tgr中会带上code信息
	gt, tgr, err := s.ValidationTokenRequest(r)
	if err != nil {
		return s.tokenError(w, err)
	}
	
    // 调用GetAccessToken 获取token info信息
	ti, err := s.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		return s.tokenError(w, err)
	}
	
    //s.GetTokenData获取token info中的access_token， token_type, expire,scope,refresh_token等信息放入map
    // s.token 把token info map以json 的形式返回给http 客户端
	return s.token(w, s.GetTokenData(ti), nil)
}

```

##### GetAccessToken获取请求信息

```
//GetAccessToken在处理授权码模式的请求时，主要是调用s.Manager.GenerateAccessToken函数
func (s *Server) GetAccessToken(ctx context.Context, gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo, error) {
	...
	switch gt {
	case oauth2.AuthorizationCode:
    	// 获取access_token最终调用的是Manager.GenerateAccessToken方法
		ti, err := s.Manager.GenerateAccessToken(ctx, gt, tgr)
		...
		return ti, nil
	case oauth2.PasswordCredentials, oauth2.ClientCredentials
    	...
    case oauth2.Refreshing:
    	...
    }
    ...
}


// Manager GenerateAccessToken主要代码如下：
// GenerateAccessToken generate the access token
func (m *Manager) GenerateAccessToken(ctx context.Context, gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo, error) {
	cli, err := m.GetClient(ctx, tgr.ClientID)  //从client store获取app client信息
	...

	if gt == oauth2.AuthorizationCode {
    	// 从token store根据code 获取token info
        // 然后删除store 中对应token的code信息,保证一个code只能使用一次
		ti, err := m.getAndDelAuthorizationCode(ctx, tgr)
		...
		tgr.UserID = ti.GetUserID()
		tgr.Scope = ti.GetScope()
		if exp := ti.GetAccessExpiresIn(); exp > 0 {
			tgr.AccessTokenExp = exp
		}
	}

	ti := models.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(tgr.UserID)
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(tgr.Scope)

	createAt := time.Now()
	ti.SetAccessCreateAt(createAt)

	// set access token expires
	gcfg := m.grantConfig(gt)
	aexp := gcfg.AccessTokenExp
	if exp := tgr.AccessTokenExp; exp > 0 {
		aexp = exp
	}
	ti.SetAccessExpiresIn(aexp)
	if gcfg.IsGenerateRefresh {
		ti.SetRefreshCreateAt(createAt)
		ti.SetRefreshExpiresIn(gcfg.RefreshTokenExp)
	}

	td := &oauth2.GenerateBasic{
		Client:    cli,
		UserID:    tgr.UserID,
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}
	
    // 传入oauth2.GenerateBasic对象td，生成access_token, refresh_token
	av, rv, err := m.accessGenerate.Token(ctx, td, gcfg.IsGenerateRefresh)
	if err != nil {
		return nil, err
	}
    
    // access_token 信息写入token info
	ti.SetAccess(av)

	if rv != "" {
		ti.SetRefresh(rv)  //refresh_token信息写入token info
	}
	
    // 更新后的token info写入token store
	err = m.tokenStore.Create(ctx, ti)
	if err != nil {
		return nil, err
	}
	
	return ti, nil
}

```
