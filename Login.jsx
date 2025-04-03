import { useState, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { AuthContext } from './MetricsUploader';

function Login() {
  const [credentials, setCredentials] = useState({ 
    username: '', 
    password: '' 
  });
  const [error, setError] = useState('');
  const [errors, setErrors] = useState({});
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [isLocked, setIsLocked] = useState(false);
  const { handleLogin } = useContext(AuthContext);
  const navigate = useNavigate();

  // Form validation
  const validate = () => {
    const newErrors = {};
    if (!credentials.username.trim()) newErrors.username = 'Username is required';
    if (!credentials.password.trim()) newErrors.password = 'Password is required';
    else if (credentials.password.length < 6) newErrors.password = 'Password must be at least 6 characters';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Handle input changes
  const handleInputChange = (e) => {
    const { id, value } = e.target;
    setCredentials(prev => ({
      ...prev,
      [id]: value
    }));
    
    // Clear error when typing
    if (errors[id]) {
      setErrors(prev => ({ ...prev, [id]: '' }));
    }
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Check if account is locked
    if (isLocked) {
      setError('Account temporarily locked. Please try again later.');
      return;
    }

    // Validate form
    if (!validate()) return;

    setIsLoading(true);
    setError('');

    try {
      const response = await axios.post('/api/login', credentials, {
        headers: {
          'Content-Type': 'application/json'
        },
        withCredentials: true,
        timeout: 5000
      });

      if (response.data.error) {
        throw new Error(response.data.error);
      }

      // Reset attempts on successful login
      setAttempts(0);

      handleLogin({
        id: response.data.id,
        username: response.data.username,
        role: response.data.role,
        email: response.data.email,
        phone: response.data.phone
      });
      
      navigate(response.data.role === 'admin' ? '/admin' : '/operator');

    } catch (err) {
      // Increment failed attempts
      const newAttempts = attempts + 1;
      setAttempts(newAttempts);

      // Lock after 3 failed attempts
      if (newAttempts >= 3) {
        setIsLocked(true);
        setTimeout(() => {
          setIsLocked(false);
          setAttempts(0);
        }, 300000); // 5 minutes lockout
      }

      // Enhanced error handling
      let errorMessage = 'Login failed';
      if (err.response) {
        errorMessage = err.response.data?.error || 
                      (err.response.status === 401 ? 
                       "Invalid username or password" : 
                       `Server error: ${err.response.status}`);
      } else if (err.request) {
        errorMessage = 'No response from server. Please try again.';
      } else if (err.message.includes('timeout')) {
        errorMessage = 'Request timeout. Please try again.';
      } else {
        errorMessage = err.message || 'Login failed';
      }

      setError(isLocked ? 
        'Account temporarily locked due to multiple failed attempts. Please try again in 5 minutes.' : 
        errorMessage);
      
      console.error('Login error:', err);

    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="login-container">
      <h2>Login</h2>
      {error && (
        <div className="error">
          <strong>Error:</strong> {error}
          {attempts > 0 && !isLocked && (
            <div className="attempts-warning">
              Attempts remaining: {3 - attempts}
            </div>
          )}
        </div>
      )}
      
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={credentials.username}
            onChange={handleInputChange}
            required
            autoComplete="username"
            aria-describedby="username-help"
            className={errors.username ? 'error-input' : ''}
          />
          {errors.username && (
            <span className="field-error">{errors.username}</span>
          )}
          <small id="username-help" className="form-text">
            Enter your registered username
          </small>
        </div>

        <div className="form-group">
          <label htmlFor="password">Password</label>
          <div className="password-input-container">
            <input
              type={showPassword ? 'text' : 'password'}
              id="password"
              value={credentials.password}
              onChange={handleInputChange}
              required
              autoComplete="current-password"
              minLength="6"
              className={errors.password ? 'error-input' : ''}
            />
            <button 
              type="button" 
              className="password-toggle"
              onClick={() => setShowPassword(!showPassword)}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? 'Hide' : 'Show'}
            </button>
          </div>
          {errors.password && (
            <span className="field-error">{errors.password}</span>
          )}
        </div>

        <button 
          type="submit" 
          className="login-button" 
          disabled={isLoading || isLocked}
          aria-busy={isLoading}
        >
          {isLoading ? (
            <>
              <span className="spinner"></span>
              <span>Logging in...</span>
            </>
          ) : isLocked ? 'Account Locked' : 'Login'}
        </button>
      </form>
    </div>
  );
}

export default Login;
