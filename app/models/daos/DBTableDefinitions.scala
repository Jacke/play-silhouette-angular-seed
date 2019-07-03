package dao

import com.mohiva.play.silhouette.api.LoginInfo
import play.api.db.slick.HasDatabaseConfigProvider
import slick.jdbc.JdbcProfile
import slick.lifted.ProvenShape.proveShapeOf

trait DBTableDefinitions {
  self: HasDatabaseConfigProvider[JdbcProfile] =>

  import profile.api._

  case class DBUser(
    id: Option[Long],
    firstName: String,
    lastName: String,
    email: String,
    avatarURL: Option[String])

  class Users(tag: Tag) extends Table[DBUser](tag, "user") {
    def id = column[Long]("id", O.PrimaryKey, O.AutoInc)
    def firstName = column[String]("first_name")
    def lastName = column[String]("last_name")
    def email = column[String]("email")
    def avatarURL = column[Option[String]]("avatar_url")

    def * =
      (id.?, firstName, lastName, email, avatarURL) <> (DBUser.tupled, DBUser.unapply)
  }

  case class DBLoginInfo(
    id: Option[Long],
    providerID: String,
    providerKey: String)

  class LoginInfos(tag: Tag) extends Table[DBLoginInfo](tag, "login_info") {
    def id = column[Long]("id", O.PrimaryKey, O.AutoInc)
    def providerId = column[String]("provider_id")
    def providerKey = column[String]("provider_key")

    def * =
      (id.?, providerId, providerKey) <> (DBLoginInfo.tupled, DBLoginInfo.unapply)
  }

  case class DBUserLoginInfo(userID: Long, loginInfoId: Long)

  class UserLoginInfos(tag: Tag)
    extends Table[DBUserLoginInfo](tag, "user_login_info") {
    def userId = column[Long]("user_id")
    def loginInfoId = column[Long]("login_info_id")

    def * =
      (userId, loginInfoId) <> (DBUserLoginInfo.tupled, DBUserLoginInfo.unapply)
  }

  case class DBPasswordInfo(
    hasher: String,
    password: String,
    salt: Option[String],
    loginInfoId: Long)

  class PasswordInfos(tag: Tag)
    extends Table[DBPasswordInfo](tag, "password_info") {
    def hasher = column[String]("hasher")
    def password = column[String]("password")
    def salt = column[Option[String]]("salt")
    def loginInfoId = column[Long]("login_info_id")

    def * =
      (hasher, password, salt, loginInfoId) <> (DBPasswordInfo.tupled, DBPasswordInfo.unapply)
  }

  case class DBOauth2Info(
    accessToken: String,
    tokenType: Option[String],
    refreshToken: Option[String],
    loginInfoId: Long)

  class OathInfos(tag: Tag)
    extends Table[DBOauth2Info](tag, "oauth_info") {
    def accessToken = column[String]("access_token")
    def tokenType = column[Option[String]]("token_type")
    def refreshToken = column[Option[String]]("refresh_token")
    def loginInfoId = column[Long]("login_info_id")

    def * =
      (accessToken, tokenType, refreshToken, loginInfoId) <> (DBOauth2Info.tupled, DBOauth2Info.unapply)
  }

  val users = TableQuery[Users]
  val loginInfos = TableQuery[LoginInfos]
  val userLoginInfos = TableQuery[UserLoginInfos]
  val passwordInfos = TableQuery[PasswordInfos]
  val oauthInfos = TableQuery[OathInfos]

  def loginInfoQuery(loginInfo: LoginInfo) =
    loginInfos.filter(dbLoginInfo =>
      dbLoginInfo.providerId === loginInfo.providerID && dbLoginInfo.providerKey === loginInfo.providerKey)
}
