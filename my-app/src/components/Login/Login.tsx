import React, { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import './Login.css';
import { useNavigate } from 'react-router-dom';

const Login = () => {
  const { login, register, isAuthenticated, error, clearErrors } = useAuth();
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    // Clear errors when switching between login and register
    clearErrors?.();
    setFormError('');
  }, [isLogin, clearErrors]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Form validation
    if (!username.trim()) {
      setFormError('Username is required');
      return;
    }
    
    if (!password.trim()) {
      setFormError('Password is required');
      return;
    }
    
    if (!isLogin && password !== confirmPassword) {
      setFormError('Passwords do not match');
      return;
    }
    
    setLoading(true);
    setFormError('');
    
    try {
      if (isLogin) {
        await login(username, password);
        navigate("/chat");
      } else {
        await register(username, password);
        setSuccess("Created user successfully!")
      }
    } catch (err) {
      console.error('Authentication error:', err);
      setFormError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const toggleMode = () => {
    setIsLogin(!isLogin);
    setUsername('');
    setPassword('');
    setConfirmPassword('');
    setFormError('');
    setSuccess('');
  };

  return (
    <div className="flex min-h-screen bg-gradient-to-br from-indigo-500 to-purple-600">
      <div className="m-auto bg-white rounded-xl shadow-2xl overflow-hidden max-w-md w-full">
        <div className="p-8">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-gray-800">
              {isLogin ? 'Welcome Back' : 'Create Account'}
            </h2>
            <p className="text-gray-500 mt-2">
              {isLogin 
                ? 'Sign in to your secure messaging account' 
                : 'Join our secure encrypted messaging platform'}
            </p>
          </div>
          
          {(error || formError) && (
            <div 
              className="bg-red-50 text-red-600 p-4 rounded-lg mb-6 text-sm"
            >
              {error || formError}
            </div>
          )}

          {success && (
            <div 
              className="bg-green-600 p-4 rounded-lg mb-6 text-sm"
            >
              {success}
            </div>
          )}
          
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-transparent transition"
                placeholder="Enter your username"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-transparent transition"
                placeholder="Enter your password"
              />
            </div>
            
            {!isLogin && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Confirm Password
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-transparent transition"
                  placeholder="Confirm your password"
                />
              </div>
            )}
            
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-indigo-500 to-purple-600 text-white font-semibold py-3 rounded-lg shadow-md hover:shadow-lg transform hover:-translate-y-0.5 transition duration-200 disabled:opacity-70 disabled:cursor-not-allowed"
            >
              {loading ? (
                <div className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Processing...
                </div>
              ) : isLogin ? 'Sign In' : 'Create Account'}
            </button>
          </form>
          
          <div className="mt-8 text-center">
            <button
              onClick={toggleMode}
              className="text-indigo-600 hover:text-indigo-800 font-medium transition"
            >
              {isLogin
                ? "Don't have an account? Sign up"
                : "Already have an account? Sign in"}
            </button>
          </div>
        </div>
        
        <div className="bg-gradient-to-r from-indigo-100 to-purple-100 p-6">
          <div className="flex items-center space-x-3 mb-4">
            <div className="bg-green-500 w-3 h-3 rounded-full"></div>
            <span className="text-sm font-medium">End-to-End Encryption</span>
          </div>
          <div className="flex items-center space-x-3 mb-4">
            <div className="bg-blue-500 w-3 h-3 rounded-full"></div>
            <span className="text-sm font-medium">Perfect Forward Secrecy</span>
          </div>
          <div className="flex items-center space-x-3">
            <div className="bg-purple-500 w-3 h-3 rounded-full"></div>
            <span className="text-sm font-medium">Message Authentication</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;