package forms

import play.api.data.Form
import play.api.data.Forms._
import play.api.libs.json.{ Json, _ }
import com.mohiva.play.silhouette.api.util.Credentials
import play.api.libs.functional.syntax._
import play.api.libs.json._

/**
 * The form which handles the sign up process.
 */
object SignUpForm {

  /**
   * A play framework form.
   */
  val form = Form(
    mapping(
      "firstName" -> nonEmptyText,
      "lastName" -> nonEmptyText,
      "email" -> email,
      "password" -> nonEmptyText
    )(Data.apply)(Data.unapply)
  )
  implicit val reader = Json.reads[Data]
  implicit val writer = Json.writes[Data]

  /**
   * The form data.
   *
   * @param firstName The first name of a user.
   * @param lastName The last name of a user.
   * @param email The email of the user.
   * @param password The password of the user.
   */
  case class Data(
    firstName: String,
    lastName: String,
    email: String,
    password: String)
}

import org.joda.time.DateTime
import play.api.libs.json._

case class Token(
  token: String,
  expiresOn: DateTime)

object Token {

  implicit object TokenWrites extends OWrites[Token] {
    def writes(token: Token): JsObject = {
      val json = Json.obj(
        "token" -> token.token,
        "expiresOn" -> token.expiresOn.toString
      )

      json
    }
  }
}

object CredentialFormat {

  implicit val restFormat = ((__ \ "identifier").format[String] ~
    (__ \ "password")
    .format[String])(Credentials.apply, unlift(Credentials.unapply))
}

