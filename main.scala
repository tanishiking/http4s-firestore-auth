//> using scala 3
//> using toolkit latest
//> using dep "com.github.jwt-scala::jwt-upickle:9.4.4"
//> using dep "org.http4s::http4s-ember-client:0.23.23"
//> using dep "io.chrisdavenport::http4s-grpc-google-cloud-firestore-v1:3.15.2+0.0.6"

// https://developers.google.com/identity/protocols/oauth2/service-account?hl=en#error-codes

import cats.syntax.all._
import cats.effect._
import org.http4s._

import org.http4s.client.Client
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.client.middleware.Logger

import com.google.firestore.v1.firestore.Firestore
import com.google.firestore.v1.document.Document
import com.google.firestore.v1.firestore.GetDocumentRequest
import com.google.firestore.v1.firestore.GetDocumentRequest.ConsistencySelector
import com.google.firestore.v1.firestore.CreateDocumentRequest
import com.google.firestore.v1.document.Value
import com.google.firestore.v1.document.Value.ValueTypeOneof

// For issuing access token
import java.time.Instant
import pdi.jwt.{JwtAlgorithm, JwtUpickle, JwtClaim, JwtHeader}
import upickle.default.*
import sttp.client4.quick.*

case class ServiceAccountCredentials(
  `type`: String,
  project_id: String,
  private_key_id: String,
  private_key: String,
  client_email: String,
  client_id: String,
  auth_uri: String,
  token_uri: String,
  client_x509_cert_url: String,
  universe_domain: String
) derives ReadWriter

case class Token(
  access_token: String,
  expires_in: Int,
  token_type: String
) derives ReadWriter

object Main extends IOApp:
  override def run(args: List[String]): IO[ExitCode] =
    val projectId: String = args(0)
    val serviceAccountKey: String = args(1)
    getAccessToken(serviceAccountKey) match
      case Left(value) => 
        IO.println(value) >> ExitCode.Error.pure[IO]
      case Right(accessToken) =>
        createDocument(projectId, accessToken) >> ExitCode.Success.pure[IO]

def createDocument(projectId: String, accessToken: String): IO[Unit] =
  def createEmberClient(): Resource[IO, Client[IO]] =
    EmberClientBuilder
      .default[IO]
      .withHttp2
      .build
  createEmberClient().use { rawClient =>
    val client = Logger[IO](
      logHeaders = true,
      logBody = true,
      redactHeadersWhen = _ => false,
      logAction = Some(msg => IO.println(msg))
    )(rawClient)
    val firestore = Firestore.fromClient(
      client,
      Uri
        .fromString("https://firestore.googleapis.com")
        .getOrElse(throw new RuntimeException("invalid firestore uri"))
    )
    val docId = System.currentTimeMillis().toString
    firestore
      .createDocument(
        CreateDocumentRequest.of(
          parent = s"projects/$projectId/databases/(default)/documents",
          collectionId = "jokes",
          documentId = docId,
          document = Some(Document.of(
            name = "",
            fields = Map(
              "joke" -> Value.of(
                ValueTypeOneof.StringValue("joke")
              )
            ),
            createTime = None,
            updateTime = None
          )),
          mask = None
        ),
        Headers.of(
          headers.Authorization(
            Credentials.Token(AuthScheme.Bearer, accessToken)
          ),
          headers.`Content-Type`(
            new MediaType("application", "grpc")
          )
        )
      )
      .flatMap { doc =>
        IO.println(doc)
      }
  }


def getAccessToken(serviceAccountKey: String): Either[RuntimeException, String] =
  val cred = read[ServiceAccountCredentials](os.read(os.pwd / serviceAccountKey))

  // Create a JWT 
  val header = JwtHeader(
    algorithm = Some(JwtAlgorithm.RS256),
    typ = Some("JWT"),
    keyId = Some(cred.private_key_id)
  )
  val claim = JwtClaim(
    expiration = Some(Instant.now.plusSeconds(60 * 60).getEpochSecond),
    issuedAt = Some(Instant.now.getEpochSecond),
    issuer = Some(cred.client_email),
    audience = Some(Set("https://oauth2.googleapis.com/token"))
  ) ++ ("scope" -> "https://www.googleapis.com/auth/datastore")
  val key = "secretKey"
  val algo = JwtAlgorithm.HS256
  val token = JwtUpickle.encode(header, claim, cred.private_key)

  // Request an access token from the Google OAuth 2.0 Authorization Server.
  val request = quickRequest
    .body(Map("grant_type" -> "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion" -> token))
    .post(uri"https://oauth2.googleapis.com/token")
  val response = request.send(backend)
  if (response.code == sttp.model.StatusCode.Ok) {
    val token = read[Token](response.body)
    Right(token.access_token)
  } else {
    Left(new RuntimeException(s"${response.code}: ${response.body}"))
  }
