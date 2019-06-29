package controllers

import java.util.UUID
import javax.inject.Inject

import com.mohiva.play.silhouette.api._
import com.mohiva.play.silhouette.api.repositories.AuthInfoRepository
import com.mohiva.play.silhouette.api.services.AvatarService
import com.mohiva.play.silhouette.api.util.PasswordHasherRegistry
import com.mohiva.play.silhouette.impl.providers._
import forms.SignUpForm
import models.User
import models.services.{ AuthTokenService, UserService }
import org.webjars.play.WebJarsUtil
import forms.{ CredentialFormat, Token }

import play.api.i18n.{ I18nSupport, Messages }
import play.api.libs.json._
import play.api.libs.mailer.{ Email, MailerClient }
import play.api.mvc.{ AbstractController, AnyContent, ControllerComponents, Request }
import utils.auth.DefaultEnv

import scala.concurrent.{ ExecutionContext, Future }

/**
 * The `Sign Up` controller.
 *
 * @param components             The Play controller components.
 * @param silhouette             The Silhouette stack.
 * @param userService            The user service implementation.
 * @param authInfoRepository     The auth info repository implementation.
 * @param authTokenService       The auth token service implementation.
 * @param avatarService          The avatar service implementation.
 * @param passwordHasherRegistry The password hasher registry.
 * @param mailerClient           The mailer client.
 * @param webJarsUtil            The webjar util.
 * @param assets                 The Play assets finder.
 * @param ex                     The execution context.
 */
class SignUpController @Inject() (
  components: ControllerComponents,
  silhouette: Silhouette[DefaultEnv],
  userService: UserService,
  authInfoRepository: AuthInfoRepository,
  authTokenService: AuthTokenService,
  avatarService: AvatarService,
  passwordHasherRegistry: PasswordHasherRegistry,
  mailerClient: MailerClient
)(
  implicit
  webJarsUtil: WebJarsUtil,
  assets: AssetsFinder,
  ex: ExecutionContext
) extends AbstractController(components) with I18nSupport {

  /**
   * Views the `Sign Up` page.
   *
   * @return The result to display.
   */
  def view = silhouette.UnsecuredAction.async { implicit request: Request[AnyContent] =>
    Future.successful(Ok(views.html.signUp(SignUpForm.form)))
  }

  /**
   * Handles the submitted form.
   *
   * @return The result to display.
   */
  def submit = Action.async(parse.json) { implicit request =>
    request.body
      .validate[SignUpForm.Data]
      .map { signUp =>
        val loginInfo = LoginInfo(CredentialsProvider.ID, signUp.email)
        userService.retrieve(loginInfo).flatMap {
          case None =>
            /* user not already exists */
            val decorateFLname: Option[String] => String = n => n.getOrElse("")
            val user = User(
              java.util.UUID.randomUUID(),
              loginInfo,
              Some(signUp.firstName),
              Some(signUp.lastName),
              Some(signUp.firstName + " " + signUp.lastName),
              Some(signUp.email),
              None,
              true)
            // val plainPassword = UUID.randomUUID().toString.replaceAll("-", "")
            val authInfo = passwordHasherRegistry.current.hash(signUp.password)
            for {
              avatar <- avatarService.retrieveURL(signUp.email)
              userToSave <- userService.save(user.copy(avatarURL = avatar))
              authInfo <- authInfoRepository.add(loginInfo, authInfo)
              authenticator <- silhouette.env.authenticatorService.create(
                loginInfo)
              token <- silhouette.env.authenticatorService.init(authenticator)
              result <- silhouette.env.authenticatorService.embed(
                token,
                Ok(
                  Json.toJson(
                    Token(
                      token = token,
                      expiresOn = authenticator.expirationDateTime))))
            } yield {
              val url =
                routes.ApplicationController.index().absoluteURL()
              mailerClient.send(Email(
                subject = Messages("email.sign.up.subject"),
                from = Messages("email.from"),
                to = Seq(user.email.get),
                bodyText = Some(views.txt.emails.signUp(user, url).body),
                bodyHtml = Some(views.html.emails.signUp(user, url).body)
              ))
              silhouette.env.eventBus.publish(SignUpEvent(user, request))
              silhouette.env.eventBus.publish(LoginEvent(user, request))
              result
            }
          case Some(_) =>
            /* user already exists! */
            Future(Conflict(Json.toJson("user already exists")))
        }
      }
      .recoverTotal {
        case error =>
          Future.successful(
            BadRequest(Json.toJson(JsError.toJson(error))))
      }
  }
}
